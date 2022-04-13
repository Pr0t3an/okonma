# okonma

Okonma is a Cross Platform forensics orchestration tool written in go. Essentially uses other tools to parse standard forensic triage images.

This was more used as a personal project to learn go - but also increase my understanding of what some forensics tools are doing a little deeper and increase the efficiency by making this cross platform - this meant having to create some of my own tools to bridge some gaps (e.g. predefetch, yarper (registry log parser). Some tasks have been preloaded and some tool downloads from the original authors are part of the instalation process - note the licensing of these tools in advance


```
 _____  _
|  _  || |
| | | || | __  ___   _ __   _ __ ___    __ _
| | | || |/ / / _ \ | '_ \ | '_ ` _ \  / _` |
\ \_/ /|   < | (_) || | | || | | | | || (_| |
 \___/ |_|\_\ \___/ |_| |_||_| |_| |_| \__,_|
usage: Okonma [-h|--help] [-i|--inputdir "<value>"] [-o|--outputdir "<value>"]
              [-s|--task "<value>"] [-t|--template "<value>"] [-p|--printt]
              [-d|--test] [-e|--envcheck]

              Go Wrapper for Forensic Tools

Arguments:

  -h  --help       Print help information
  -i  --inputdir   Input Directory
  -o  --outputdir  Output Directory
  -s  --task       Executes a single task by name or number
  -t  --template   Executes a template by name or number
  -p  --printt     Display List the list of templates/tasks
  -d  --test       QuickTest Func
  -e  --envcheck   Environment Check

  ```
  to start run with okanoma -e (may take a couple of runs, to check dontnet6, and download unpack some tools) 
  
  1) requires python3
  2) requires sqllite
  3) requires dotnet6
  4) downloads zimmerman tools
  5) downloads predefetch
  6) downloads hindsight
  
  will download any dependencys to /forensictools (same place you can add to if you are adding custom tools)
```  
   _____  _
|  _  || |
| | | || | __  ___   _ __   _ __ ___    __ _
| | | || |/ / / _ \ | '_ \ | '_ ` _ \  / _` |
\ \_/ /|   < | (_) || | | || | | | | || (_| |
 \___/ |_|\_\ \___/ |_| |_||_| |_| |_| \__,_|
[+] DotNet Core 6.x Successfully Detected
[+] SQLlite Successfully Detected
[+] Python3 Successfully Detected
[-] Hindisght missing, downloading
git clone https://github.com/obsidianforensics/hindsight.git /Users/pr0t3an/Desktop/okonma/forensictools/hs
/Users/pr0t3an/Desktop/okonma
[+] Hindsight Requirements Installed 
[+] Hindsight appears to be working normally
[-] Prefetch Parser repo has not been detected
git clone https://github.com/Pr0t3an/predfetch.git /Users/pr0t3an/Desktop/okonma/forensictools/pfp
pip3 install -r '/Users/Pr0t3an/Desktop/okonma/forensictools/pfp/requirements.txt'
/Users/pr0t3an/Desktop/okonma
[+] PrefetchParser Requirements Installed 
[-] Zimmerman tools missing. Downloading
file already exists, if looking to update run -u
unzipping..


```
The tool itself does not perform any forensics aquisition or analysis - rather ties tools that do this together.

Utilises heavily Zimmerman Tools for many of the parsing tasks - https://ericzimmerman.github.io/#!index.md <--- these are awesome, the .net6 compilations bring ability to run those across multiple devices

For Areas I feel other tools provide better / different outputs have substituted those in, but essentially this really just executes the tasks defined - so can be expanded on as needed.

Configuration stored in JSON files
Config
  --> tasks.json - example
  
  This defines a task via TaskName, if you add custom tools - drop the file into /forensics directory
  
      {
      "TaskId": "6",
      "TaskName": "PreDefech",
      "Directory" : "ProgramExecution",
      "TaskDescription": "Runs Python Prefetch Parser",
      "RequiredSource": "na",
      "Tasking": "-i %sourceDirectory% -c -o %destinationDirectory%/prefetcj.csv",
      "Executable": "PreDefech.py",
      "Caller": "Python3"
    }
    
   TaskId - mostly unused - but who doesnt like a bit of order
   TasKName - how you call a task in a template
   Directory - where the parsed data is stored
   Task Description - descriptor of the task
   RequiredSource - filename of the specific artifact to be parsed i.e. ActivitesCache.db for Windows Timeline parsing
   Tasking - essentially the command line thats run (isnt a fancy tool - uses shell commands) 
    substitutions
        %sourceDirectory - the source directory of evidence
        %destinationDirectory% - the desintation dir is passed from script execution + will append the chosen dirs
        %requiredSource% - required source - inserts in the required actifact (removes need to hardcode)
        %sqlquery% --> special used for Activites cache Parsing (removes need to hardcode paths)
        %rebpath% --> special used for registry parsing with Kroll(removes need to hardcode paths)
        
        
        
        
 templates.json 
    Templates basically run a collection of tasks - may have a few specific to a few artifacts e.g. $mft, evtx, browser history - which you can save in a template. Or run everything - which can be another.
    
    {
      "TemplateName": "FolderAccess",
      "ExecutedTasks": "SBECmdZim,WxTCmdZim,LeCmdZim,JLECmdZim",
      "Description" : "Runs all folder access tools"
    }
    
    TemplateName - how you call it
    What tasks from tasks.json you will run
    Description
    
    
  Directories.json
  
  Defines and creates standard directory structure for artifacts - forcing to define them, vs hardcoding them in the tasks should make for better (repeatable organisation)
  
    {
      "Directory": "FileSystem",
      "Description": "File System Output"

    },
    
    
  
  A few things still to be polished - planned release mid April
  
  - Completion of yarper - to merge log files into reg hives
  - Tidy the ActivitiesCache Parsing 
  - multithread






*** Any packages deployed tools deployed after installation - please check licensing of those tool. No warranty implied***
