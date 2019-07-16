package main

import (
	"log"
	"github.com/gocolly/colly"
	"fmt"
	"regexp"
	"net/http"
	"os"
	"time"
	"flag"
)

type CollyData struct {

	url string
	barsuchiha int //response status code with a authorized session 
	anonymous int //response status code without the authorized session 
}

var (
	
	Auth_url *string = flag.String("auth_uri", "", "uri, ex. -auth_uri=/login")
	Login_form *string = flag.String("lf", "", "Login_form, ex -lf=user_form")
	Pass_form *string = flag.String("pf", "", "Pass_form, ex. -pf=pass_form")
	Domain *string = flag.String("host", "", "hostname or ip-address, ex. -host=1.1.1.1")
	User *string = flag.String("u", "", "username, ex. -u=John")
	Pass *string = flag.String("p", "", "password, ex. -p=changeit")
	Port *string = flag.String("Port", "", ":Port (optional, ex. -Port=:80)")
)

func main() {
	
	filename := "WARNING_" + time.RFC3339 + ".txt"
	file, fileErr := os.Create(filename)
	if fileErr != nil {
		log.Fatal(fileErr)
		os.Exit(1)	
	}
	defer file.Close()

	flag.Parse()
	if *Domain == "" || *User == "" || *Pass == "" "" *Auth_url == "" || *Login_form == "" || *Pass_form == ""  {
		fmt.Println("\x1b[91m","\x1b[1m")
		fmt.Println("Error")
		fmt.Println("\x1b[39m","\x1b[21m")
		flag.Usage()
		return
	}  

	crawler(file, *Domain, *User, *Pass, *Port)
}

//Function create Colly Collector with authorized session

func crawler(file *os.File, Domain string, User string, Pass string, Port string) {

	str := &CollyData{}

	// create a new collector
	logout := regexp.MustCompile(`(logout)$`)
	c := colly.NewCollector(
		colly.AllowedDomains(Domain),
		colly.UserAgent("turbobarsuchiha"),
		colly.DisallowedURLFilters(logout),
	)
	
	// authenticate

	err := c.Post("http://"+Domain + Port + Auth_url, map[string]string{Login_form: User, Pass_form: Pass})
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
		result(str.barsuchiha, str.anonymous, str.url, file)
	})

	// start scraping
	c.Visit("http://"+Domain+Port)

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

func result (barsuchiha, anonymous int, url string, file *os.File) {


	if barsuchiha == anonymous {
		 fmt.Fprintln(file, "WARNING:", url)
	}

}
