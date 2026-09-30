package datagen

const DefaultLoginPath = "/login"

var SensitivePaths = []string{
	"/.env",
	"/.git/config",
	"/.git/HEAD",
	"/.htaccess",
	"/.htpasswd",
	"/.npmrc",
	"/.ssh/id_rsa",
	"/.aws/credentials",
	"/.well-known/security.txt",
	"/wp-admin",
	"/wp-login.php",
	"/admin",
	"/administrator",
	"/backup.zip",
	"/backup.sql",
	"/backup.tar.gz",
	"/config.php",
	"/config.yaml",
	"/config.json",
	"/database.yml",
	"/docker-compose.yml",
	"/Dockerfile",
	"/actuator/health",
	"/actuator/env",
	"/server-status",
	"/phpmyadmin",
	"/debug",
	"/console",
	"/shell.php",
}

var FuzzParams = []string{"id", "debug", "admin", "token", "cmd", "redirect", "file"}
