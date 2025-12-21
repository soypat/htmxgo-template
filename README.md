# htmxgo-template
Minimal OAuth application using HTMX+Templ+Go with Key-Value store and SSE toasts.

All you need to get started with your next million dollar idea.

Priorities of this template are: Security and Readability/Simplicity.

Performance was taken into account in API design- You should be able to scale this application up without modifying the API used in HTTP endpoints.

To run:
```sh
# generate templates.
go generate
# run application in developer mode as user.
go run . -dev=user
# run viewing application as if you were administrator.
go run . -dev=admin
```

![image](https://private-user-images.githubusercontent.com/26156425/528987966-5682c87d-27ca-4f70-b7ce-4efa2af090dd.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NjYzMzQ5MzEsIm5iZiI6MTc2NjMzNDYzMSwicGF0aCI6Ii8yNjE1NjQyNS81Mjg5ODc5NjYtNTY4MmM4N2QtMjdjYS00ZjcwLWI3Y2UtNGVmYTJhZjA5MGRkLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNTEyMjElMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjUxMjIxVDE2MzAzMVomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTZmMmEyZGI5OTQzM2IwYjNlMTRkZDk1ODVlOTNmZGI2MjgyMjY4NWY4NzBmNzgwNDUwNjRiZGNiMzU5NGQ4YmImWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.gV6v16HGQ6_wXbpy1UZivsjNOosS0wSXYF0ciOF6aBY)
