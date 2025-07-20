package templates

import (
	"embed"
	"html/template"
	"net/http"
	"github.com/gin-gonic/gin"
)

//go:embed *.html
var templateFS embed.FS

var templates *template.Template

func init() {
	var err error
	templates, err = template.ParseFS(templateFS, "*.html")
	if err != nil {
		panic("Failed to parse templates: " + err.Error())
	}
}

type SuccessData struct {
	Email     string
	FirstName string
	LastName  string
}

type PendingData struct {
	Email     string
	FirstName string
	LastName  string
}

type ErrorData struct {
	Message string
}

type JoinReasonData struct {
	Email     string
	FirstName string
	LastName  string
	UserID    int
}

func RenderSuccess(c *gin.Context, data SuccessData) {
	c.Header("Content-Type", "text/html")
	c.Status(http.StatusOK)
	if err := templates.ExecuteTemplate(c.Writer, "success.html", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error")
	}
}

func RenderPending(c *gin.Context, data PendingData) {
	c.Header("Content-Type", "text/html")
	c.Status(http.StatusOK)
	if err := templates.ExecuteTemplate(c.Writer, "pending.html", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error")
	}
}

func RenderError(c *gin.Context, data ErrorData) {
	c.Header("Content-Type", "text/html")
	c.Status(http.StatusOK)
	if err := templates.ExecuteTemplate(c.Writer, "error.html", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error")
	}
}

func RenderJoinReason(c *gin.Context, data JoinReasonData) {
	c.Header("Content-Type", "text/html")
	c.Status(http.StatusOK)
	if err := templates.ExecuteTemplate(c.Writer, "join_reason.html", data); err != nil {
		c.String(http.StatusInternalServerError, "Template error")
	}
}
