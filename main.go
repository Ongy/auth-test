package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	cookieName = "special-auth-cookie"
	token      = "TOKENVALUE"
)

func doAuthorize(w http.ResponseWriter, req *http.Request) {
	var auth string
	cookies := req.Cookies()
	for _, cookie := range cookies {
		fmt.Printf("Cookie: %v\n", cookie)
		if cookie.Name == cookieName {
			auth = cookie.Value
		}
	}

	fmt.Printf("auth: %q\n", auth)
	if auth == "" {
		fmt.Println("Unauthorized: no auth cookie")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if auth != token {
		fmt.Println("Unauthorized: wrong auth cookie")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Println("Authorized")
}

func setToken(w http.ResponseWriter, req *http.Request) {
	// This should really be done with a fragment in the URL and a bit of JS
	// But it's easier to script server-side only
	token := req.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing Fragment", http.StatusBadRequest)
		return
	}

	redirect := req.URL.Query().Get("target")
	if redirect == "" {
		http.Error(w, "Missing target", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/"})
	http.Redirect(w, req, redirect, http.StatusFound)
}

func doRun(ctx context.Context) error {
	http.DefaultServeMux.HandleFunc("/authorize", doAuthorize)
	http.DefaultServeMux.HandleFunc("/settoken", setToken)

	server := http.Server{
		Addr: ":8081",
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()

		server.Close()
		stop()
	}()

	fmt.Printf("Going to listen and server\n")
	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}

	return nil
}

func main() {
	if err := doRun(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Execution error: %v\n", err)
		os.Exit(1)
	}
}
