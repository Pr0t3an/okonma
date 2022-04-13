package main

//Checklist
//zimmerman tools
//hindsight
//Regripper
import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/common-nighthawk/go-figure"
	ct "github.com/daviddengcn/go-colortext"
	"github.com/h2non/filetype"
	"github.com/kardianos/osext"
	"github.com/olekukonko/tablewriter"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var executiondir string
var zimfilename string = "All_6.zip"
var tasklist [][]string
var sourcedir string
var destdir string
var templatepath string
var taskpath string
var stagedtasks [][]string

//get where go binary is located
func getexecutiondir() {
	programdir, err := osext.ExecutableFolder()
	if err != nil {
		log.Fatal(err)
	}
	executiondir = programdir
}

//define Templates Json
type Templates struct {
	Templates []Template `json:templates`
}

type Template struct {
	TemplateName  string `json:TemplateName`
	ExecutedTasks string `json:ExecutedTasks`
	Description   string `json:Description`
}

type Tasks struct {
	Tasks []Task `json:tasks`
}

type Task struct {
	TaskId          string `json:TaskId`
	TaskName        string `json:TaskName`
	Directory       string `json:Directory`
	TaskDescription string `json:TaskDescription`
	Tasking         string `json:Tasking`
	RequiredSource  string `json:RequiredSource`
	Executable      string `json:Executable`
	Caller          string `json:Caller`
}

func loadtemplates(filename string) {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Outputting Templates")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var templates Templates
	json.Unmarshal(byteValue, &templates)
	table := tablewriter.NewWriter(os.Stdout)

	table.SetHeader([]string{"Template Name", "Executed Tasks", "Description"})
	for i := 0; i < len(templates.Templates); i++ {

		data := [][]string{[]string{templates.Templates[i].TemplateName, templates.Templates[i].ExecutedTasks, templates.Templates[i].Description}}
		for _, v := range data {
			table.Append(v)
		}
	}
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("-")
	table.Render()
}

func loadtasks(filename string) {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Outputing Tasks")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var tasks Tasks
	json.Unmarshal(byteValue, &tasks)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Task ID", "Task Name", "Directory", "Description", "Tasking", "Source File", "Executable", "Caller"})
	for i := 0; i < len(tasks.Tasks); i++ {
		data := [][]string{[]string{tasks.Tasks[i].TaskId, tasks.Tasks[i].TaskName, tasks.Tasks[i].Directory, tasks.Tasks[i].TaskDescription, tasks.Tasks[i].Tasking, tasks.Tasks[i].RequiredSource, tasks.Tasks[i].Executable, tasks.Tasks[i].Caller}}
		for _, v := range data {
			table.Append(v)
		}
	}
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()
}

// next section is dedicated to ensuring host is configured fully

func getHindsight() {
	var clonestring string = "git clone https://github.com/obsidianforensics/hindsight.git " + executiondir + "/forensictools/hs"
	fmt.Println(clonestring)
	executeshell(clonestring)
	fmt.Println(executiondir)
}

func getPrefetchparser() {
	var clonestring string = "git clone https://github.com/Pr0t3an/predfetch.git " + executiondir + "/forensictools/pfp"
	fmt.Println(clonestring)
	executeshell(clonestring)
	var tmpstr string = "pip3 install -r '" + executiondir + "/forensictools/pfp/requirements.txt'"
	executeshell(tmpstr)
	fmt.Println(tmpstr)
	fmt.Println(executiondir)
}

func envchecks() {

	if strings.Contains(executeshell("dotnet --list-runtimes"), "6.") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] DotNet Core 6.x Successfully Detected")
		ct.ResetColor()

	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("[+] DotNet Missing required to run Zimmerman Tools - recommend using brew install dotnet")
		ct.ResetColor()
	}

	if strings.Contains(executeshell("sqlite3 --version"), "3.") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] SQLlite Successfully Detected")
		ct.ResetColor()

	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("[+] Sqlite3 Missing required for Activities Cache parsing - recommend using brew install sqlite")
		ct.ResetColor()
	}

	if strings.Contains(executeshell("python3 --version"), "Python 3.") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Python3 Successfully Detected")
		ct.ResetColor()

	}

	if strings.Contains(executeshell("ls "+executiondir+"/forensictools/hs | wc -l"), "1") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Hindsight repo has been detected")
		ct.ResetColor()
	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("[-] Hindisght missing, downloading")
		ct.ResetColor()
		getHindsight()
		executeshell("pip3 install -r '" + executiondir + "/forensictools/hs/requirements.txt'")
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Hindsight Requirements Installed ")
		ct.ResetColor()

	}
	var cmdstring string = "python3 '" + executiondir + "/forensictools/hs/hindsight.py' -h"
	//fmt.Println(cmdstring)
	if strings.Contains(executeshell(cmdstring), "Hindsight") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Hindsight appears to be working normally")
		ct.ResetColor()

	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("Hindisght Encountered an error -manual check needed")
		ct.ResetColor()

	}
	if strings.Contains(executeshell("ls "+executiondir+"/forensictools/pfp | head -n1 | wc -l"), "1") {
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Prefetch Parser repo has been detected")
		ct.ResetColor()
	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("[-] Prefetch Parser repo has not been detected")
		ct.ResetColor()
		getPrefetchparser()
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] PrefetchParser Requirements Installed ")
		ct.ResetColor()

	}

	if strings.Contains(executeshell("ls "+executiondir+"/forensictools/*.dll | wc -l"), "1") {
		//fmt.Println(executiondir + "/forensictools/")
		ct.Foreground(ct.Green, false)
		fmt.Println("[+] Zimmerman Tools seem to be deployed")
		ct.ResetColor()

	} else {
		ct.Foreground(ct.Red, false)
		fmt.Println("[-] Zimmerman tools missing. Downloading")
		ct.ResetColor()
		downloadZim()
		downloadZim()

	}

}

//function to download a file

func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

//failed the zimmerman check - so need to donwload
func downloadZim() {
	//check if actually needed to download
	if _, err := os.Stat(zimfilename); err == nil {
		// path/to/whatever exists
		if checkfiletype(zimfilename) {
			println("file already exists, if looking to update run -u")
			println("unzipping..")
			unzipzim()
		} else {
			println("downloaded file is not a valid archive. Possibly proxy/cert issue. Delete All_6.zip and retry")
		}

	} else if errors.Is(err, os.ErrNotExist) {
		fileUrl := "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/All_6.zip"
		err := DownloadFile(zimfilename, fileUrl)
		if err != nil {
			panic(err)
			fmt.Println("1")
		}
		if checkfiletype(zimfilename) {
			fmt.Println("Downloaded: " + fileUrl)
		} else {
			println("downloaded file is not a valid archive. Possibly proxy/cert issue. Delete All_6.zip and retry")
		}
	} else {
		println("Schrodingers file: are files even real")

	}
}

func unzipzim() {
	files, err := Unzip(zimfilename, executiondir+"/forensictools")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Unzipped:\n" + strings.Join(files, "\n"))
	fmt.Println("=====")
	for _, element := range files {
		files, err := Unzip(element, executiondir+"/forensictools")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Unzipped:\n" + strings.Join(files, "\n"))

	}

}

func unzippper(input string, output string) {
	files, err := Unzip(input, output)
	if err != nil {
		ct.Foreground(ct.Red, false)
		fmt.Println("[+] Please manually unpack file and rerun")
		log.Fatal(err)

		ct.ResetColor()
	}

	fmt.Println("Unzipped:\n" + strings.Join(files, "\n"))
	fmt.Println("=====")
	for _, element := range files {
		files, err := Unzip(element, output)
		if err != nil {
			ct.Foreground(ct.Red, false)
			fmt.Println("[+] Please manually unpack file and rerun")
			log.Fatal(err)

			ct.ResetColor()
		}
		fmt.Println("Unzipped:\n" + strings.Join(files, "\n"))

	}

}

func Unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

func checkfiletype(filename string) bool {
	buf, _ := ioutil.ReadFile(filename)
	var status bool
	status = false
	if filetype.IsArchive(buf) {
		status = true
	}
	return status
}

//execute shell function - this is heavily re-used for all tool runnings and env checks
func executeshell(vCommand string) (vOutput string) {

	out, err := exec.Command("bash", "-c", vCommand).Output()
	if err != nil {
		fmt.Println("error in execution")
		//log.Fatal(err)

	}
	vOutput = string(out)
	return

}

//simplifying the getting of tasks then executing
// this is the main function that reads task configs and GYSHIDOs (15 tasks in default template)

func getoutputinorder(filetocreate string) {
	_, err := os.Stat("err")
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(filetocreate, 0755)
		if errDir != nil {
			log.Fatal(err)
		}
	}
}

func getinputinorder() {
	//check if its an archive file
	if checkfiletype(sourcedir) {
		ct.Foreground(ct.Cyan, false)
		fmt.Println("Input File is an archive - staging archive in output directory")
		ct.ResetColor()
		unzippper(sourcedir, destdir+"/unpacked")
		sourcedir = destdir + "/unpacked"
		ct.Foreground(ct.Cyan, false)
		fmt.Println("Temp Sourcedir:" + sourcedir)
		ct.ResetColor()
	}
}

func findyoself(findme string) []string {
	var s []string
	err := filepath.Walk(sourcedir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			//fmt.Println(path)
			if strings.HasSuffix(path, findme) {
				s = append(s, path)
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}
	return s

}

func runtaskings(taskid string, tpath string) {
	tasklings := [][]string{}
	tasklings = gettaskings(taskid, tpath)
	getinputinorder()
	getoutputinorder(destdir)
	//				taskling := []string{tasks.Tasks[i].TaskName0, tasks.Tasks[i].Directory1, tasks.Tasks[i].TaskDescription2, tasks.Tasks[i].Tasking3, tasks.Tasks[i].RequiredSource4, tasks.Tasks[i].Executable5, tasks.Tasks[i].Caller6}
	for i := 0; i < len(tasklings); i++ {
		//pull out dedup'd list of directors and create outputstructure
		getoutputinorder(destdir + "/" + tasklings[i][1])

		if tasklings[i][4] == "na" {

			stagingtask := tasklings[i][3]
			stagingtask = strings.ReplaceAll(stagingtask, "%sourceDirectory%", sourcedir)
			stagingtask = strings.ReplaceAll(stagingtask, "%destinationDirectory%", destdir+"/"+tasklings[i][1])
			if tasklings[i][5] == "" {
				stagingtask = tasklings[i][6] + " " + stagingtask
			} else {
				stagingtask = tasklings[i][6] + " " + executiondir + "/forensictools/" + tasklings[i][5] + " " + stagingtask
			}
			stagingtask = strings.ReplaceAll(stagingtask, "%rebpath%", executiondir+"/forensictools/RECmd/rebs/")
			stagingtask = strings.ReplaceAll(stagingtask, "%sqlquery%", executiondir+"/config/WindowsTimeline.sql")
			//fmt.Println(stagingtask)
			staging := []string{tasklings[i][0], stagingtask}
			stagedtasks = append(stagedtasks, staging)

		} else {
			fileinput := findyoself((tasklings[i][4]))
			//fmt.Println(fileinput)
			if len(fileinput) > 1 {
				var ts string
				//if there is more than 1 matching file need to handle this well
				//fmt.Println(tasklings[i][0] + " has " + strconv.Itoa(len(fileinput)) + " files")
				for x := 0; x < len(fileinput); x++ {
					//fmt.Println(fileinput[x])
					if strings.Contains(fileinput[x], "Users") {
						m := regexp.MustCompile(`Users\/(?:[a-zA-Z0-9_\-]*)`)
						da := (m.FindAllString(fileinput[x], -1))
						ts = (da[(len(da) - 1)])
						ts = strings.ReplaceAll(ts, "Users/", "")

						ts = destdir + "/" + tasklings[i][1] + "/" + ts
						getoutputinorder(ts)

					} else {
						ts = (strconv.Itoa(x) + tasklings[i][0])
					}
					stagingtask := tasklings[i][3]
					stagingtask = strings.ReplaceAll(stagingtask, "%requiredSource%", fileinput[x])
					stagingtask = strings.ReplaceAll(stagingtask, "%destinationDirectory%", ts)
					if tasklings[i][5] == "" {
						stagingtask = tasklings[i][6] + " " + stagingtask

					} else {

						stagingtask = tasklings[i][6] + " " + executiondir + "/forensictools/" + tasklings[i][5] + " " + stagingtask
					}
					stagingtask = strings.ReplaceAll(stagingtask, "%sqlquery%", executiondir+"/config/WindowsTimeline.sql")
					//fmt.Println(stagingtask)
					staging := []string{tasklings[i][0], stagingtask}
					stagedtasks = append(stagedtasks, staging)
				}

			} else if len(fileinput) == 1 {
				//simple one starting here - single file
				stagingtask := tasklings[i][3]
				stagingtask = strings.ReplaceAll(stagingtask, "%requiredSource%", fileinput[0])
				stagingtask = strings.ReplaceAll(stagingtask, "%destinationDirectory%", destdir+"/"+tasklings[i][1])
				if tasklings[i][5] == "" {
					stagingtask = tasklings[i][6] + " " + stagingtask
				} else {
					stagingtask = tasklings[i][6] + " " + executiondir + "/forensictools/" + tasklings[i][5] + " " + stagingtask
				}
				stagingtask = strings.ReplaceAll(stagingtask, "%sqlquery%", executiondir+"/config/WindowsTimeline.sql")
				//fmt.Println(stagingtask)
				//p23
				//				taskling := []string{tasks.Tasks[i].TaskName, tasks.Tasks[i].Directory, tasks.Tasks[i].TaskDescription, tasks.Tasks[i].Tasking, tasks.Tasks[i].RequiredSource, tasks.Tasks[i].Executable, tasks.Tasks[i].Caller}
				//				taskslice = append(taskslice, taskling)
				staging := []string{tasklings[i][0], stagingtask}
				stagedtasks = append(stagedtasks, staging)

			} else if len(fileinput) == 0 {
				//no specific files found of this type - thus will be skipped
				ct.Foreground(ct.Red, true)
				fmt.Println("[+] Artifacts Matching Task: " + tasklings[i][0] + " Artifact: " + tasklings[i][4] + " not found in source")
				ct.ResetColor()
			}

		}

	}

}

// s option chosen - looking for task config
func gettaskings(taskid string, tpath string) [][]string {

	taskid = strings.ToLower(taskid)
	taskid = strings.ReplaceAll(taskid, " ", "")
	s := strings.Split(taskid, ",")
	taskslice := [][]string{}
	ct.Foreground(ct.Cyan, false)
	fmt.Println("Number of tasks to run: " + strconv.Itoa(len(s)))
	fmt.Println("[+] Searching for task(s): " + taskid)
	ct.ResetColor()
	jsonFile, err := os.Open(tpath)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var tasks Tasks
	json.Unmarshal(byteValue, &tasks)
	b := len(s)
	for i := 0; i < len(tasks.Tasks); i++ {
		for d := 0; d < b; d++ {
			if strings.ToLower(tasks.Tasks[i].TaskId) == s[d] {
				ct.Foreground(ct.Green, true)
				fmt.Println("[+] Matching Task ID found - Queuing Execution " + tasks.Tasks[i].TaskName)
				ct.ResetColor()
				taskling := []string{tasks.Tasks[i].TaskName, tasks.Tasks[i].Directory, tasks.Tasks[i].TaskDescription, tasks.Tasks[i].Tasking, tasks.Tasks[i].RequiredSource, tasks.Tasks[i].Executable, tasks.Tasks[i].Caller}
				taskslice = append(taskslice, taskling)

			} else if strings.ToLower(tasks.Tasks[i].TaskName) == s[d] {

				ct.Foreground(ct.Green, true)
				fmt.Println("[+] Matching Task Name found - Queuing Execution " + tasks.Tasks[i].TaskName)
				ct.ResetColor()
				taskling := []string{tasks.Tasks[i].TaskName, tasks.Tasks[i].Directory, tasks.Tasks[i].TaskDescription, tasks.Tasks[i].Tasking, tasks.Tasks[i].RequiredSource, tasks.Tasks[i].Executable, tasks.Tasks[i].Caller}
				taskslice = append(taskslice, taskling)

			} else if i == (cap(tasks.Tasks)) && d == (cap(s)) {
				ct.Foreground(ct.Red, true)
				fmt.Println("[+] No Matching Task Found - run -l to see all available tasks")
				ct.ResetColor()
			}
		}
	}
	return taskslice
}

func launcher() {
	//p22
	for i := 0; i < len(stagedtasks); i++ {
		fmt.Println(stagedtasks[i][1])
		executeshell(stagedtasks[i][1])
	}

}

func kickoffatemplate(tempid string, tpath string) {
	tempid = strings.ToLower(tempid)
	ct.Foreground(ct.Cyan, false)
	fmt.Println("[+] Searching for template: " + tempid)
	ct.ResetColor()
	jsonFile, err := os.Open(tpath)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var templates Templates
	json.Unmarshal(byteValue, &templates)
	var matchedtask string
	s := 0
	for i := 0; i < len(templates.Templates); i++ {
		if strings.ToLower(templates.Templates[i].TemplateName) == tempid {
			ct.Foreground(ct.Green, true)
			fmt.Println("[+] Matching Template Name found - Gathering Tasks")
			matchedtask = strings.ToLower(templates.Templates[i].ExecutedTasks)
			fmt.Println("[+] Following Tasks will be Retrieved: " + matchedtask)
			ct.ResetColor()
			s++
		} else if i == (cap(templates.Templates)) && s == 0 {
			//} else if i == (cap(tasks.Tasks)) && i == (cap(s)) {
			ct.Foreground(ct.Red, true)
			fmt.Println("[+] No Matching Template Found - run -l to see all available templates")
			ct.ResetColor()
			log.Fatal(err)
		}

	}
	runtaskings(matchedtask, "config/tasks.json")
	launcher()
}

func main() {
	getexecutiondir()
	totesimportant := figure.NewFigure("Okonma", "doom", true)
	totesimportant.Print()
	parser := argparse.NewParser("Okonma", "Go Wrapper for Forensic Tools")
	i := parser.String("i", "inputdir", &argparse.Options{Required: false, Help: "Input Directory"})
	o := parser.String("o", "outputdir", &argparse.Options{Required: false, Help: "Output Directory"})
	s := parser.String("s", "task", &argparse.Options{Required: false, Help: "Executes a single task by name or number"})
	t := parser.String("t", "template", &argparse.Options{Required: false, Help: "Executes a template by name or number"})
	var printfunc *bool = parser.Flag("p", "printt", &argparse.Options{Required: false, Help: "Display List the list of templates/tasks"})
	var testfunc *bool = parser.Flag("d", "test", &argparse.Options{Required: false, Help: "QuickTest Func"})
	var envcheck *bool = parser.Flag("e", "envcheck", &argparse.Options{Required: false, Help: "Environment Check"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))

	}

	//assign to global vars
	templatepath = "config/templates.json"
	taskpath = "config/tasks.json"
	getexecutiondir()

	//var sourcedir string
	//var destdir string

	if len(*i) > 0 {
		sourcedir = *i
	}
	if len(*o) > 0 {
		destdir = *o
	}

	if (*printfunc) == true {
		ct.Foreground(ct.Green, true)
		fmt.Println("\n[+] Templates can be modified via" + executiondir + "/" + templatepath)
		ct.ResetColor()
		loadtemplates(templatepath)
		ct.Foreground(ct.Green, true)
		fmt.Println("\n[+] Tasks can be modified via" + executiondir + "/" + taskpath)
		ct.ResetColor()
		loadtasks(taskpath)
	}

	if len(*s) > 0 {
		fmt.Println("single task")
		if len(*i) > 0 && len(*o) > 0 {
			runtaskings(*s, "config/tasks.json")
			launcher()
		} else {
			ct.Foreground(ct.Red, true)
			fmt.Println("[+] Either Input (-i) or Output (-o) is missing")
			ct.ResetColor()
			fmt.Print(parser.Usage(err))
			log.Fatal(err)
		}
	}

	if len(*t) > 0 {
		if len(*i) > 0 && len(*o) > 0 {
			fmt.Println("Template")
			kickoffatemplate(*t, "config/templates.json")
		} else {
			ct.Foreground(ct.Red, true)
			fmt.Println("[+] Either Input (-i) or Output (-o) is missing")
			ct.ResetColor()
			fmt.Print(parser.Usage(err))
			log.Fatal(err)
		}
	}

	if (*envcheck) == true {
		envchecks()
	}

	if (*testfunc) == true {
		fmt.Println("Input File/Dir: " + *i)
		fmt.Println("Output Dir: " + *o)
		//fmt.Println((executiondir))
		//envchecks()

	}

}
