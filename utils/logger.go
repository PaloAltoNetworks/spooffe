package utils

import (
	"fmt"
	"os"
	"time"
)

func FormatLogLine(message string, value interface{}, level string) string {
	prefix := "[*]"
	prefixColor := Yellow
	msgColor := Green
	valueColor := Reset

	switch level {
	case "success":
		prefix = "[+]"
		prefixColor = Blue
	case "warning":
		prefix = "[!]"
		prefixColor = Magenta
	case "error":
		prefix = "[!]"
		prefixColor = Red
	case "title":
		prefix = ""
		prefixColor = Cyan + Bold
		msgColor = Cyan + Bold
	}

	output := fmt.Sprintf("%s%s%s%s %s%s%s",
		Bold, prefixColor, prefix, Reset,
		msgColor, message, Reset,
	)

	if value != nil {
		output += fmt.Sprintf(" %s%v%s", valueColor, value, Reset)
	}

	return output
}

func Log(msg string, value interface{}, level string) {
	output := FormatLogLine(msg, value, level)

	fmt.Println(output)
}

var fileLogger *os.File

func InitFileLogger() error {
	path := "/tmp/spooffe.log"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	fileLogger = f
	return nil
}

func CloseFileLogger() {
	if fileLogger != nil {
		fileLogger.Close()
	}
}

func LogToFile(msg string) {
	if fileLogger == nil {
		return
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(fileLogger, "%s %s\n", timestamp, msg)
}

// func Log(msg string, value interface{}, level string) {
// 	prefix := "[*]"
// 	prefixColor := Yellow
// 	msgColor := Green
// 	valueColor := Reset

// 	switch level {
// 	case "success":
// 		prefix = "[+]"
// 		prefixColor = Blue
// 	case "warning":
// 		prefix = "[!]"
// 		prefixColor = Magenta
// 	case "error":
// 		prefix = "[!]"
// 		prefixColor = Red
// 	case "title":
// 		prefix = ""
// 		prefixColor = Cyan + Bold
// 		msgColor = Cyan + Bold
// 	}

// 	output := fmt.Sprintf("%s%s%s%s %s%s%s",
// 		Bold, prefixColor, prefix, Reset,
// 		msgColor, msg, Reset,
// 	)

// 	if value != nil {
// 		output += fmt.Sprintf(" %s%v%s", valueColor, value, Reset)
// 	}

// 	fmt.Println(output)
// }
