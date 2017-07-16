all: isuda

deps:
	go get github.com/go-sql-driver/mysql
	go get github.com/gorilla/mux
	go get github.com/gorilla/sessions
	go get github.com/Songmu/strrand
	go get github.com/unrolled/render

isuda: deps
	go build -o isuda isuda.go type.go util.go

.PHONY: all deps
