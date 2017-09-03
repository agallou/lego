// Package gandibeta implements a DNS provider for solving the DNS-01
// challenge using Gandi DNS.
package online

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
        "net/url"
	"github.com/xenolf/lego/acme"
)

// Gandi API reference:       http://doc.livedns.gandi.net/

var (
	// endpoint is the Gandi API endpoint used by Present and
	// CleanUp. It is overridden during tests.
	endpoint = "https://api.online.net/api/v1"
	// findZoneByFqdn determines the DNS zone of an fqdn. It is overridden
	// during tests.
	findZoneByFqdn = acme.FindZoneByFqdn
)

// inProgressInfo contains information about an in-progress challenge
type inProgressInfo struct {
	fieldName string
	authZone  string
        domainId int
        previousVersionUuid string
        newVersionUuid string
}

// DNSProvider is an implementation of the
// acme.ChallengeProviderTimeout interface that uses Gandi's XML-RPC
// API to manage TXT records for a domain.
type DNSProvider struct {
	apiKey          string
	inProgressFQDNs map[string]inProgressInfo
	inProgressMu    sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Gandi.
// Credentials must be passed in the environment variable: GANDI_API_KEY.
func NewDNSProvider() (*DNSProvider, error) {
	apiKey := os.Getenv("ONLINE_API_KEY")
	return NewDNSProviderCredentials(apiKey)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Gandi.
func NewDNSProviderCredentials(apiKey string) (*DNSProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("No Online API Key given")
	}
	return &DNSProvider{
		apiKey:          apiKey,
		inProgressFQDNs: make(map[string]inProgressInfo),
	}, nil
}

// Present creates a TXT record using the specified parameters. It
// does this by creating and activating a new temporary Gandi DNS
// zone. This new zone contains the TXT record.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value, ttl := acme.DNS01Record(domain, keyAuth)
	if ttl < 300 {
		ttl = 300 // 300 is gandi minimum value for ttl
	}
	// find authZone and Gandi zone_id for fqdn
	authZone, err := findZoneByFqdn(fqdn, acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Online DNS: findZoneByFqdn failure: %v", err)
	}
	// determine name of TXT record
	if !strings.HasSuffix(
		strings.ToLower(fqdn), strings.ToLower("."+authZone)) {
		return fmt.Errorf(
			"Online DNS: unexpected authZone %s for fqdn %s", authZone, fqdn)
	}
	name := fqdn[:len(fqdn)-len("."+authZone)]
	// acquire lock and check there is not a challenge already in
	// progress for this value of authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()
	// perform API actions to create and activate new gandi zone
	// containing the required TXT record
	err = d.addTXTRecord(acme.UnFqdn(authZone), name, value, ttl, authZone, fqdn)
	if err != nil {
		return err
	}
	return nil
}

// CleanUp removes the TXT record matching the specified
// parameters. It does this by restoring the old Gandi DNS zone and
// removing the temporary one created by Present.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _ := acme.DNS01Record(domain, keyAuth)
	// acquire lock and retrieve zoneID, newZoneID and authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()
	if _, ok := d.inProgressFQDNs[fqdn]; !ok {
		// if there is no cleanup information then just return
		return nil
	}
	fieldName := d.inProgressFQDNs[fqdn].fieldName
	authZone := d.inProgressFQDNs[fqdn].authZone
        domainId := d.inProgressFQDNs[fqdn].domainId
        previousVersionUuid := d.inProgressFQDNs[fqdn].previousVersionUuid
        newVersionUuid := d.inProgressFQDNs[fqdn].newVersionUuid
	delete(d.inProgressFQDNs, fqdn)
	// perform API actions to restore old gandi zone for authZone
	err := d.deleteTXTRecord(acme.UnFqdn(authZone), fieldName, domainId, previousVersionUuid, newVersionUuid)
	if err != nil {
		return err
	}
	return nil
}

// Timeout returns the values (40*time.Minute, 60*time.Second) which
// are used by the acme package as timeout and check interval values
// when checking for DNS record propagation with Gandi.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 20 * time.Minute, 20 * time.Second
}

// types for JSON method calls and parameters

type addFieldRequest struct {
	RRSetTTL    int      `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
}

type deleteFieldRequest struct {
	Delete bool `json:"delete"`
}

// types for JSON responses

type onlineApiDomainStruct struct {
	Id int
	Name string
}

type onlineApiVersionStruct struct {
	Uuid_ref string
 	Active bool
}

type onlineApiRecordStruct struct {
	Name string
	Type string
	Ttl int
	Data string
}

// POSTing/Marshalling/Unmarshalling


func (d *DNSProvider) sendRequest(method string, resource string, form url.Values) (*bytes.Buffer, error) {
	url := fmt.Sprintf("%s/%s", endpoint, resource)

        req, err := http.NewRequest(method, url, strings.NewReader(form.Encode()))
        
	if err != nil {
		return nil, err
	}

        if (method == "POST" || method == "PATCH") {
               req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        } 

	if len(d.apiKey) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", d.apiKey))
	}

	client := &http.Client{Timeout: time.Duration(10 * time.Second)}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
                buf := new(bytes.Buffer)
                buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("Online API request %s %s failed with HTTP status code %d : %s", method, resource, resp.StatusCode, buf.String())
	}

        buf := new(bytes.Buffer)
        buf.ReadFrom(resp.Body)

	return buf, nil
}

func (d *DNSProvider) callOnlineToGetDomainId(domain string) (int, error) {
        form := url.Values{}
        var domainId int;

	target := fmt.Sprintf("domain")
	responseBuffer, err := d.sendRequest("GET", target, form)
        if err != nil {
	  return domainId, err
	}

        response := make([]onlineApiDomainStruct, 0)
        json.Unmarshal(responseBuffer.Bytes(), &response)

        for _, element := range response {
          if (element.Name != domain) {
            continue;
          }
          domainId = element.Id
        }

        if (domainId == 0) {
          return domainId, fmt.Errorf("Domain not found on online API")
        }

        return domainId, nil
}

func (d *DNSProvider) callOnlineToGetActiveVersion(domainId int) (string, error) {
        form := url.Values{}
        var versionUuid string;

	target := fmt.Sprintf("domain/%d/version", domainId)
	responseBuffer, err := d.sendRequest("GET", target, form)
        if err != nil {
	  return versionUuid, err
	}

        response := make([]onlineApiVersionStruct, 0)
        json.Unmarshal(responseBuffer.Bytes(), &response)

        for _, element := range response {
          if (!element.Active) {
            continue;
          }
          versionUuid = element.Uuid_ref
        }

        if (0 == len(versionUuid)) {
          return versionUuid, fmt.Errorf("Version not found on online API")
        }
        return versionUuid, nil
}

func (d *DNSProvider) callOnlineToAddRecord(domainId int, versionUuid string, name string, typeValue string, ttl int, data string) error {
        form := url.Values{}
        form.Add("name", name)
        form.Add("type", typeValue)
        form.Add("priority", "12")
        form.Add("ttl", fmt.Sprintf("%d", ttl))
        form.Add("data", data)

	target := fmt.Sprintf("domain/%d/version/%s/zone", domainId, versionUuid)
	_, err := d.sendRequest("POST", target, form)
        if err != nil {
	  return err
	}

        return nil;
}

func (d *DNSProvider) callOnlineToCreateVersion(domainId int) (string, error) {
        form := url.Values{}
        form.Add("name", "LE temporary version")

        var newUuidVersion string

	target := fmt.Sprintf("domain/%d/version", domainId)
	responseBuffer, err := d.sendRequest("POST", target, form)
        if err != nil {
	  return newUuidVersion, err
	}

	var response onlineApiVersionStruct
	err = json.NewDecoder(responseBuffer).Decode(&response)

        return response.Uuid_ref, nil;
}

func (d *DNSProvider) callOnlineToActivateVersion(domainId int, version string) error {
        form := url.Values{}
	target := fmt.Sprintf("domain/%d/version/%s/enable", domainId, version)
	_, err := d.sendRequest("PATCH", target, form)
        if err != nil {
	  return err
	}
        return nil
}

func (d *DNSProvider) callOnlineToDeleteVersion(domainId int, version string) error {
        form := url.Values{}
	target := fmt.Sprintf("domain/%d/version/%s", domainId, version)
	_, err := d.sendRequest("DELETE", target, form)
        if err != nil {
	  return err
	}
        return nil
}



func (d *DNSProvider) callOnlineToCloneZone(domainId int) (string, error) {
        form := url.Values{}
        var newVersionUuid string;

	target := fmt.Sprintf("domain/%d/zone", domainId)
	responseBuffer, err := d.sendRequest("GET", target, form)
        if err != nil {
	  return newVersionUuid, err
	}

        response := make([]onlineApiRecordStruct, 0)
        json.Unmarshal(responseBuffer.Bytes(), &response)

        // appel pour créer la zone vide
        newVersionUuid, err = d.callOnlineToCreateVersion(domainId)

        for _, record := range response {
          d.callOnlineToAddRecord(domainId, newVersionUuid, record.Name, record.Type, record.Ttl, record.Data)
//          versionUuid = element.Uuid_ref
        }

/*

        if (0 == len(versionUuid)) {
          return versionUuid, fmt.Errorf("Version not found on online API")
        }*/
        return newVersionUuid, nil
}



// functions to perform API actions

func (d *DNSProvider) addTXTRecord(domain string, name string, value string, ttl int, authZone string, fqdn string) error {

        domainId, err := d.callOnlineToGetDomainId(domain)
        if err != nil {
		return err
	}

        versionUuid, err := d.callOnlineToGetActiveVersion(domainId)
        newVersionUuid, err := d.callOnlineToCloneZone(domainId)

        if err != nil {
		return err
	}

	err = d.callOnlineToAddRecord(domainId, newVersionUuid, name, "TXT", ttl, value)
        if err != nil {
		return err
	}

        err = d.callOnlineToActivateVersion(domainId, newVersionUuid)
        if err != nil {
		return err
	}

	// save data necessary for CleanUp
	d.inProgressFQDNs[fqdn] = inProgressInfo{
		authZone:  authZone,
		fieldName: name,
                domainId: domainId,
                previousVersionUuid: versionUuid,
                newVersionUuid: newVersionUuid,
	}

	return err
}

func (d *DNSProvider) deleteTXTRecord(domain string, name string, domainId int, previousVersionUuid string, newVersionUuid string) error {

        err := d.callOnlineToActivateVersion(domainId, previousVersionUuid)
        if err != nil {
		return err
	}

        err = d.callOnlineToDeleteVersion(domainId, newVersionUuid)
        if err != nil {
		return err
	}

	return nil
}
