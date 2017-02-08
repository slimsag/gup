package main

import (
	"fmt"
	"log"
	"time"

	"github.com/slimsag/gup"
)

func main() {
	// Configure and start Gup.
	gup.Config.PublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJdQBqUwH7Qea9/fK4EercIuoZvi\nzWEQBvXvcljnWZ0jb07zm0WRoAoh0jy9sEA5wfvZclZjnsV84TVevHYdwA==\n-----END PUBLIC KEY-----\n"
	gup.Config.UpdateURL = "http://storage.googleapis.com/my-bucket/updates/$GUP"
	gup.Config.CheckInterval = 5 * time.Second // For production, you'll want to use something larger
	gup.Start()

	// Wait for updates to become available.
	<-gup.UpdateAvailable
	fmt.Println("an update is available!")

	// Perform the update.
	_, err := gup.Update()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("update successful, please relaunch the program")
}
