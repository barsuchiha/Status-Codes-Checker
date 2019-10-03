package main

import (
	"os"
	"fmt"
	"flag"
	"log"
	"time"
	"net/smtp"	
	"net/mail"
	"net/http"
	"errors"
	"regexp"
	"io"
	"io/ioutil"
	s "strings"
	b "encoding/base64"
	"github.com/beevik/etree"
	"github.com/scorredoira/email"
	"github.com/gocolly/colly"
	"golang.org/x/crypto/ssh/terminal"
	"bytes"
	"crypto/tls"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

var (
	Name_xml string
	Mail_login string
	Mail_password string
	Mail_from string
	Mail_to string
	Mail_host string
	Mail_port string
	Http_Https string
	Auth_url string
	Login_form string
	Pass_form string
	Domain string
	Port string
	User_login string
	User_password string
	Name_xml_file string
	Name_warning_file string
	Name_smpt_xml_file string = "mail_setting.xml"
	Warning_file *os.File
	Portal_xml_file *os.File
	Smpt_xml_file *os.File
	Config *string = flag.String("c", "", ":Config (optional, ex. -c test.xml)")
	Key_1 = []byte("key AES")
	Key_2 = []byte("key AES")
)

type loginAuth struct {
  username, password string
}

func check_error(e error) {  
	if e != nil {
		file, err := os.OpenFile("crawler.log",  os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
   			if err != nil {
			log.Println("Error log file")
		}
		fmt.Fprintln(file, (time.Now().Format("2006-01-02_15:04")), e)
	}
}

func data_input_portal() {
    fmt.Print("Enter Name_xml : ")
    fmt.Scanln(&Name_xml)
    fmt.Print("Enter Http(s): ")
    fmt.Scanln(&Http_Https)
    fmt.Print("Enter Domain: ")
    fmt.Scanln(&Domain)
    fmt.Print("Enter Port:")
    fmt.Scanln(&Port)
    fmt.Print("Enter Auth_url: ")
    fmt.Scanln(&Auth_url)
    fmt.Print("Enter Login_form: ")
    fmt.Scanln(&Login_form)
    fmt.Print("Enter Pass_form: ")
    fmt.Scanln(&Pass_form)
    fmt.Print("Enter User_login: ")
    fmt.Scanln(&User_login)
    fmt.Print("Enter User_password: ")
    bytePassword, err := terminal.ReadPassword(0)
	if err == nil {
		fmt.Print("\n")
	}
	password := string(bytePassword)
	User_password = s.TrimSpace(password)
}

func data_iput_smtp() {	
	fmt.Print("Enter Mail_login: ")
    fmt.Scanln(&Mail_login)
    fmt.Print("Enter Mail_password: ")
    bytePassword, err := terminal.ReadPassword(0)
	if err == nil {
		fmt.Print("\n")
	}
	password := string(bytePassword)
	Mail_password = s.TrimSpace(password)
    fmt.Print("Enter Mail_to: ")
    fmt.Scanln(&Mail_to)
    fmt.Print("Enter Mail_host: ")
    fmt.Scanln(&Mail_host)
    fmt.Print("Enter Mail_port: ")
    fmt.Scanln(&Mail_port)
}

func create_xml_portal_setting() {
	data_input_portal()
	create_portal_xml_file()
    doc := etree.NewDocument()
    doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
    portal_setting_p := doc.CreateElement("Portal_Setting")
    portal_name := portal_setting_p.CreateElement("Name_xml")
    portal_name.CreateAttr("Name_xml", Name_xml)
    http_p := portal_setting_p.CreateElement("Http_s")
    http_p.CreateAttr("Http_s", Http_Https)  
    host := portal_setting_p.CreateElement("Host")
    host.CreateAttr("Host", Domain)
    port := portal_setting_p.CreateElement("Port")
    port.CreateAttr("Port", Port)
    auth_uri := portal_setting_p.CreateElement("Auth_uri")
    auth_url := b.StdEncoding.EncodeToString([]byte(Auth_url))
    auth_uri.CreateAttr("Auth_uri", auth_url)
    login_form := portal_setting_p.CreateElement("Login_form")
    login_form.CreateAttr("Login_form", Login_form)
    pass_form := portal_setting_p.CreateElement("Pass_form")
    pass_form.CreateAttr("Pass_form", Pass_form)
    portal_login := portal_setting_p.CreateElement("Portal_login")
    portal_login.CreateAttr("Portal_login", User_login)
    portal_pass := portal_setting_p.CreateElement("Portal_pass")
    pswd, _ := encrypt(Key_1, User_password)
    portal_pass.CreateAttr("Portal_pass", pswd)
    doc.Indent(2)
    doc.WriteTo(Portal_xml_file)	
}

func create_xml_smtp_setting() {
	create_smtp_xml_file()
	doc := etree.NewDocument()
    doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
    smtp_setting_p := doc.CreateElement("Smtp_Setting")
    mail_login := smtp_setting_p.CreateElement("Mail_login")
    mail_login.CreateAttr("Mail_login", Mail_login)
    mail_password := smtp_setting_p.CreateElement("Mail_password")
    pswd, _ := encrypt(Key_2, Mail_password)
    mail_password.CreateAttr("Mail_password", pswd)
    mail_from := smtp_setting_p.CreateElement("Mail_from")
    mail_from.CreateAttr("Mail_from", Mail_login)
    mail_to := smtp_setting_p.CreateElement("Mail_to")
    mail_to.CreateAttr("Mail_to", Mail_to)
    mail_host := smtp_setting_p.CreateElement("Mail_host")
    mail_host.CreateAttr("Mail_host", Mail_host)
    mail_port := smtp_setting_p.CreateElement("Mail_port")
    mail_port.CreateAttr("Mail_port", Mail_port)
    doc.Indent(2)
    doc.WriteTo(Smpt_xml_file)
}

func check_flag() {
	flag.Parse()
	if *Config == "" {
	 	create_xml_portal_setting()
	} else if *Config != "" {
		Name_xml_file = *Config
		if _, err := os.Stat(Name_xml_file); os.IsNotExist(err) {
		create_xml_portal_setting()
		}
	}
}

func create_warning_file(){


	Name_warning_file = "WARNING_" + Name_xml + "_" + time.Now().Format("2006-01-02_15:04") + ".txt"
	file, err := os.OpenFile(Name_warning_file,  os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		check_error(err)
	}
	Warning_file = file
}

func create_portal_xml_file() {
	Name_xml_file = Name_xml + ".xml"
	file, err := os.OpenFile(Name_xml_file,  os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        check_error(err)
    }
    Portal_xml_file = file
}
func create_smtp_xml_file() {
	file, err := os.OpenFile(Name_smpt_xml_file,  os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
    if err != nil {
        check_error(err)
    }
    Smpt_xml_file = file
}
func xml_parser_portal() {
	doc := etree.NewDocument()
	if err := doc.ReadFromFile(Name_xml_file); err != nil {
	        check_error(err)
	}
	root := doc.SelectElement("Portal_Setting")
	for _, portal_name_p := range root.SelectElement("Name_xml").Attr {
		Name_xml = portal_name_p.Value
	}

    for _, host_p := range root.SelectElement("Host").Attr {
        Domain = host_p.Value
    }
    for _, http_p := range root.SelectElement("Http_s").Attr {
    	Http_Https = http_p.Value
    }
    for _, port_p := range root.SelectElement("Port").Attr {
        if port_p.Value != "" {
        	Port = ":" + port_p.Value
        }
    }
    for _, auth_uri_p := range root.SelectElement("Auth_uri").Attr {
        decoded, err := b.StdEncoding.DecodeString(auth_uri_p.Value)
		if err != nil {
			check_error(err)
		return
		}
        Auth_url = string(decoded)
    }
    for _, login_form_p := range root.SelectElement("Login_form").Attr {
        Login_form = login_form_p.Value
    }
    for _, pass_form_p := range root.SelectElement("Pass_form").Attr {
        Pass_form = pass_form_p.Value
    }
    for _, portal_login_p := range root.SelectElement("Portal_login").Attr {
        User_login = portal_login_p.Value
    }
    for _, portal_pass_p := range root.SelectElement("Portal_pass").Attr {
        pswd, _ := decrypt(Key_1, portal_pass_p.Value)
        User_password = pswd
    }
}

func xml_parser_smtp() {
	doc := etree.NewDocument()
    if err := doc.ReadFromFile(Name_smpt_xml_file); err != nil {
        check_error(err)
    }
    root := doc.SelectElement("Smtp_Setting")
    for _, mail_login_p := range root.SelectElement("Mail_login").Attr {
        Mail_login = mail_login_p.Value
    }
    for _, mail_password_p := range root.SelectElement("Mail_password").Attr {
        pswd, _ := decrypt(Key_2, mail_password_p.Value)
        Mail_password = pswd
    }
    for _, mail_from_p := range root.SelectElement("Mail_from").Attr {
        Mail_from = mail_from_p.Value
    }
    for _, mail_from_p := range root.SelectElement("Mail_to").Attr {
        Mail_to = mail_from_p.Value
	}
	for _, mail_host_p := range root.SelectElement("Mail_host").Attr {
        Mail_host = mail_host_p.Value
    }
    for _, mail_port_p := range root.SelectElement("Mail_port").Attr {
        Mail_port = mail_port_p.Value
    }
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}
func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}
func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}

func send() {
	m := email.NewMessage("Liferay crawler report", "Done " + Name_warning_file)
	m.From = mail.Address{Name: "Crawler", Address: Mail_from}
	m.To = []string{Mail_to}
	if err := m.Attach(Name_warning_file); err != nil {
		check_error(err)
	}
	auth := LoginAuth(Mail_login, Mail_password)
	hst := Mail_host + ":" + Mail_port
	if err := email.Send(hst, auth, m); err != nil {
		check_error(err)
	}
}

func crawler(){

	logout := regexp.MustCompile(`(logout)$`)
	c := colly.NewCollector(
		colly.AllowedDomains(Domain),
		colly.UserAgent("Turbo_barsuchiha/1.0"),
		colly.DisallowedURLFilters(logout),
	)
	c.WithTransport(&http.Transport{
    	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	Proxy: http.ProxyFromEnvironment, // ignore expired SSL certificates
    	})
	err := c.Post(Http_Https + "://"+Domain + Port + Auth_url, map[string]string{Login_form: User_login, Pass_form: User_password})
	if err != nil {	
		check_error(err)
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
		url := string(r.Ctx.Get("url"))
		barsuchiha := r.StatusCode
		anonymous, anonymous_body_login_page, anonymous_body_alert := http_client(url)		
		result(barsuchiha, anonymous, url, anonymous_body_login_page, anonymous_body_alert)
	})
		// start scraping
	c.Visit(Http_Https + "://"+Domain+Port)
}

func http_client(url string) (int, bool, bool) {
	client := &http.Client{	
		//stopping redirect
		Transport: &http.Transport{
    	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    	Proxy: http.ProxyFromEnvironment,
    	},
		CheckRedirect: func(req_status *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req_status, err := http.NewRequest("GET", url, nil)
	if err != nil {
		check_error(err)
	}
	req_status.Header.Add("User-Agent", "Anonymous/1.0")
	resp_status, err := client.Do(req_status)
	if err != nil { 
		check_error(err)
	}
	content_len, err := ioutil.ReadAll(resp_status.Body)
	if err != nil {
		check_error(err)
	}
	defer resp_status.Body.Close()
	anonymous_body_login_page := s.Contains(string(content_len), "_com_liferay_login_web_portlet_LoginPortlet_mvcRenderComman")
	anonymous_body_alert := s.Contains(string(content_len), "alert alert-danger")
	return resp_status.StatusCode, anonymous_body_login_page, anonymous_body_alert
} 

func result (barsuchiha, anonymous int, url string, anonymous_body_login_page bool, anonymous_body_alert bool) {
	if barsuchiha == anonymous {
		if anonymous_body_login_page == true {
		} else if anonymous_body_alert == true {
			fmt.Fprintln(Warning_file, "POSSIBLE DISCLOSURE OF SENSITIVE INFORMATION IN HTML: ", url)	
		} else {
			fmt.Fprintln(Warning_file, "WARNING: ", url)
		}
	}
}

func closeFile() {
    Warning_file.Close()
    Smpt_xml_file.Close()
    Portal_xml_file.Close()
}

func addBase64Padding(value string) string {
    m := len(value) % 4
    if m != 0 {
        value += s.Repeat("=", 4-m)
    }
    return value
}

func removeBase64Padding(value string) string {
    return s.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
    padding := aes.BlockSize - len(src)%aes.BlockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
    length := len(src)
    unpadding := int(src[length-1])
    if unpadding > length {
        return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
    }

    return src[:(length - unpadding)], nil
}

func encrypt(key []byte, text string) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    msg := Pad([]byte(text))
    ciphertext := make([]byte, aes.BlockSize+len(msg))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
    finalMsg := removeBase64Padding(b.URLEncoding.EncodeToString(ciphertext))
    return finalMsg, nil
}

func decrypt(key []byte, text string) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        check_error(err)
    }
    decodedMsg, err := b.URLEncoding.DecodeString(addBase64Padding(text))
    if err != nil {
        check_error(err)
    }
    if (len(decodedMsg) % aes.BlockSize) != 0 {
        return "", errors.New("blocksize must be multipe of decoded message length")
    }
    iv := decodedMsg[:aes.BlockSize]
    msg := decodedMsg[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(msg, msg)
    unpadMsg, err := Unpad(msg)
    if err != nil {
        return "", err
    }
    return string(unpadMsg), nil
}

func main() {
	check_flag()
	if _, err := os.Stat("mail_setting.xml"); os.IsNotExist(err) {
		data_iput_smtp()
		create_xml_smtp_setting()
	}
	xml_parser_smtp()
	xml_parser_portal()
	create_warning_file()	
	fmt.Fprintln(Warning_file, ("Start " + time.Now().Format("15:04 02-01-2006")))
	crawler()
	fmt.Fprintln(Warning_file, ("Done " + time.Now().Format("15:04 02-01-2006")))
	closeFile()
	send()
}

