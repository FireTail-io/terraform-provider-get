package get

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"fmt"
	"net/url"
	"net/http"
	"os"
	"strings"
	"errors"

	"github.com/hashicorp/go-getter/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

type Releases []struct {
    AssetsUrl string `json:"assets_url"`
    TagName string `json:"tag_name"`
}

type Assets []struct {
    Name string `json:"name"`
    Url string `json:"url"`
}

func resourceArtifact() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceArtifactCreate,
		ReadContext:   resourceArtifactRead,
		UpdateContext: resourceArtifactUpdate,
		DeleteContext: resourceArtifactDelete,

		CustomizeDiff: resourceArtifactCustomizeDiff,

		Schema: map[string]*schema.Schema{
			"archive": {
				Type:        schema.TypeString,
				Description: "configure explicit unarchiving behavior",
				Optional:    true,
				ForceNew:    true,
			},
			"required": {
				Type:        schema.TypeBool,
				Description: "ensure destination is always present",
				Optional:    true,
				Default:     false,
			},
			"checksum": {
				Type:        schema.TypeString,
				Description: "configure artifact checksumming",
				Optional:    true,
				ForceNew:    true,
			},
			"dest": {
				Type:        schema.TypeString,
				Description: "destination path",
				Required:    true,
				ForceNew:    true,
			},
			"insecure": {
				Type:        schema.TypeBool,
				Description: "disable TLS verification",
				Optional:    true,
			},
			"mode": {
				Type:             schema.TypeString,
				Description:      "get mode (any, file, dir)",
				Optional:         true,
				Default:          "any",
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"any", "dir", "file"}, false)),
			},
			"sum": {
				Type:        schema.TypeString,
				Description: "artifact checksum",
				Computed:    true,
			},
			"sum64": {
				Type:        schema.TypeString,
				Description: "base64 encoded artifact checksum",
				Computed:    true,
			},
			//"url": {
			//	Type:        schema.TypeString,
			//	Description: "path to artifact (go-getter url)",
			//	Required:    true,
			//},
			"workdir": {
				Type:        schema.TypeString,
				Description: "working directory",
				Optional:    true,
				ForceNew:    true,
			},
                        "repo_org": {
                                Type:        schema.TypeString,
                                Description: "github repository organisation",
                                Required:    true,
                                ForceNew:    true,
                        },
                        "repo_name": {
                                Type:        schema.TypeString,
                                Description: "github repository name",
                                Required:    true,
                                ForceNew:    true,
                        },
			"release_version": {
                                Type:        schema.TypeString,
				Description: "github release version (release tag)",
                                Required:    true,
                                ForceNew:    true,
			},
                        "release_file": {
                                Type:        schema.TypeString,
                                Description: "github release file name",
                                Required:    true,
                                ForceNew:    true,
                        },
		},
	}
}

func resourceArtifactCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
        repoOrg := d.Get("repo_org").(string)
        repoName := d.Get("repo_name").(string)
        releaseVer := d.Get("release_version").(string)
        releaseFile := d.Get("release_file").(string)
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
                return diag.FromErr(errors.New("GITHUB_TOKEN environment variable not set!"))
	}

        // Get release request
        relReq, err := http.NewRequest("GET", "https://api.github.com/repos/"+repoOrg+"/"+repoName+"/releases", nil)
	relReq.Header.Set("Authorization", "Bearer " + token)
	relReq.Header.Set("Accept", "application/vnd.github+json")
	relReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
        relClient := &http.Client{}
	relRes, err := relClient.Do(relReq)
        if err != nil {
                return diag.FromErr(errors.New("Cannot access Github release API endpoint."))
        }
        defer relRes.Body.Close()
        relBody, err := io.ReadAll(relRes.Body)

        var releases Releases
        json.Unmarshal(relBody, &releases)

        var assetsUrl string
        for i := 0; i < len(releases); i++ {
                if releases[i].TagName == releaseVer {
                        assetsUrl = releases[i].AssetsUrl
                }
        }

        // Get assets request
        assetsReq, err := http.NewRequest("GET", assetsUrl, nil)
        assetsReq.Header.Set("Authorization", "Bearer " + token)
        assetsReq.Header.Set("Accept", "application/vnd.github+json")
        assetsReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	assetsClient := &http.Client{}
	assetsRes, err := assetsClient.Do(assetsReq)
        if err != nil {
                return diag.FromErr(errors.New("Cannot access Github assets API endpoint."))
        }
        defer assetsRes.Body.Close()
        assetsBody, err := io.ReadAll(assetsRes.Body)

        var assets Assets
        json.Unmarshal(assetsBody, &assets)

        var assetUrl string
        for i := 0; i < len(assets); i++ {
                if assets[i].Name == releaseFile {
                        assetUrl = assets[i].Url
                }
        }

	req, err := resourceArtifactRequest(d)
	if err != nil {
		return diag.FromErr(err)
	}

        src, err := url.Parse(assetUrl)
        if err != nil {
                return diag.FromErr(err)
        }
        params := src.Query()

        if archive, ok := d.GetOk("archive"); ok {
                params.Set("archive", archive.(string))
        }
        if checksum, ok := d.GetOk("checksum"); ok {
                params.Set("checksum", checksum.(string))
        }
        if insecure := d.Get("insecure").(bool); insecure {
                params.Set("insecure", fmt.Sprintf("%v", insecure))
        }
        src.RawQuery = params.Encode()
        req.Src = src.String()

        if pwd, ok := d.GetOk("workdir"); ok {
                req.Pwd = pwd.(string)
        }

	// setup a http header construct
        header := &http.Header{}

	// initialize the default values for go getter
        getters := getter.Getters
        client := m.(*getter.Client)

	// if getAllHeaders does not exist with empty string, we use the default configuration without headers
	if token == "" {
                client.Getters = getters
	} else {
                header.Add("Authorization", "Bearer " + token)
		header.Add("Accept", "application/octet-stream")
		header.Add("X-GitHub-Api-Version", "2022-11-28")
		// add the header which we did above ^^^
                httpGetter := &getter.HttpGetter{
                        Header: *header,
                }

		// set the getter to use HttpGetter
                getters = []getter.Getter{
                        httpGetter,
                }

		// set the Getters to use the getters abvove
	        getter.Getters = getters
		// intiialize the client with the getter
                client = m.(*getter.Client)
	}

	_, err = client.Get(ctx, req)
	if err != nil {
		return diag.Errorf("error getting url: %v", err)
	}

	req, err = resourceArtifactRequest(d)
	if err != nil {
		return diag.FromErr(err)
	}

	checksum, err := client.GetChecksum(ctx, req)
	if err != nil {
		return diag.Errorf("error getting checksum: %v", err)
	}
	if sum, sum64, ok := resourceArtifactSum(checksum); ok {
		d.Set("sum", sum)
		d.Set("sum64", sum64)
		d.SetId(sum)
	} else {
		sha256.New().Sum([]byte(req.Src))
		d.SetId(base64.RawStdEncoding.EncodeToString(sha256.New().Sum([]byte(req.Src))))
	}

	return resourceArtifactRead(ctx, d, m)
}

func resourceArtifactRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceArtifactUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if _, always := d.GetChange("required"); always.(bool) {
		if _, err := os.Stat(d.Get("dest").(string)); err != nil {
			return resourceArtifactCreate(ctx, d, m)
		}
	}
	return nil
}

func resourceArtifactDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	dest := d.Get("dest").(string)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Remove(dest); err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}

// resourceArtifactCustomizeDiff will ensure update when remote artifact checksum has changed
func resourceArtifactCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
	_, alwaysiface := d.GetChange("required")
	always := alwaysiface.(bool)
	if always {
		if _, err := os.Stat(d.Get("dest").(string)); err != nil {
			d.ForceNew("required")
			return nil
		}
	}

	req, err := resourceArtifactRequest(d)
	if err != nil {
		return err
	}

	checksum, err := m.(*getter.Client).GetChecksum(ctx, req)
	if err != nil {
		return fmt.Errorf("error getting checksum: %v", err)
	}

	prev, hasPrevious := d.GetOk("sum")
	if sum, _, ok := resourceArtifactSum(checksum); ok && (!hasPrevious || prev != sum) {
		d.ForceNew("sum")
		d.ForceNew("sum64")
	}

	return nil
}

// configProvider is a simplified abstraction of a ResourceData or ResourceDiff value
type configProvider interface {
	Get(string) interface{}
	GetOk(string) (interface{}, bool)
}

// resourceArtifactRequest generates a go-getter request from a ResourceData or ResourceDiff value
func resourceArtifactRequest(d configProvider) (*getter.Request, error) {
	req := &getter.Request{
		Dst: d.Get("dest").(string),
	}

	switch d.Get("mode").(string) {
	case "any":
		req.GetMode = getter.ModeAny
	case "dir":
		req.GetMode = getter.ModeDir
	case "file":
		req.GetMode = getter.ModeFile
	default:
		return nil, fmt.Errorf("expected mode to be one of [any, dir, file], got: %s", d.Get("mode").(string))
	}

	return req, nil
}

// resourceArtifactSum extracts the hex and base64 formatted sum from a FileChecksum value
func resourceArtifactSum(checksum *getter.FileChecksum) (string, string, bool) {
	if checksum == nil {
		return "", "", false
	}
	sum := checksum.String()
	sumSegments := strings.SplitN(sum, ":", 2)
	if len(sumSegments) != 2 {
		return sum, "", true
	}

	raw, err := hex.DecodeString(sumSegments[1])
	if err != nil {
		return sum, "", true
	}

	return sum, base64.StdEncoding.EncodeToString(raw), true
}
