package main

import (
	"log"
	"github.com/gocolly/colly"
	"fmt"
	"regexp"
	"net/http"

)

type CollyData struct {

	url string
	barsuchiha int //response status code with a authorized session 
	anonymous int //response status code without the authorized session 
}

func main() {

	crawler()
}

//Function create Colly Collector with authorized session

func crawler() {

	str := &CollyData{}

	// create a new collector
	logout := regexp.MustCompile(`(logout)$`)
	c := colly.NewCollector(
		colly.AllowedDomains("***"),
		colly.UserAgent("turbobarsuchiha"),
		colly.DisallowedURLFilters(logout),
	)
	
	// authenticate

	auth_url := "***"
	login_form := "***"
	pass_form := "***"
	user := "***"
	pass := "***"

	err := c.Post(auth_url, map[string]string{login_form: user, pass_form: pass})
	if err != nil {
		log.Fatal(err)
	}

	//On every a element which has href attribute call callback
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		c.Visit(e.Request.AbsoluteURL(link))
	})

	// Request unic url

	c.OnRequest(func(r *colly.Request) {
		r.Ctx.Put("url", r.URL.String())
	})

	// Analysis response

	c.OnResponse(func(r *colly.Response) {

		str.url = string(r.Ctx.Get("url"))
		str.barsuchiha = r.StatusCode
		str.anonymous = http_client(str.url) 		
		result(str.barsuchiha, str.anonymous, str.url)
	})

	// start scraping
	c.Visit("http://***")

}

//Function create the simple client without authorized session

func http_client(url string) int{

	client := &http.Client{	
		//stopping redirect
		CheckRedirect: func(req_status *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}


	req_status, req_statusErr := http.NewRequest("GET", url, nil)
	if req_statusErr != nil {
		log.Println(req_statusErr)
	}

	resp_status, resp_statusErr := client.Do(req_status)
	if resp_statusErr != nil { 
		log.Println(resp_statusErr)
	}
	defer resp_status.Body.Close()
	return resp_status.StatusCode
} 

//Function waits for answers with the same response status

func result (barsuchiha, anonymous int, url string) {

	if barsuchiha == anonymous {
			fmt.Println("WARNING:", url)
	}
}
