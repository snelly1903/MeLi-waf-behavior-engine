package datagen

// DefaultLoginPath es el endpoint de login que comparten los perfiles
// legítimos (tarea 0.4) y el generador de credential stuffing (tarea
// 0.5) — así el ataque apunta exactamente a la misma aplicación que
// navegan los usuarios reales, no a una simulada aparte.
const DefaultLoginPath = "/login"

// SensitivePaths es el vocabulario "tipo wordlist" que usa el generador
// de escaneo lento (slowscan.go): rutas típicas de fuzzing de
// superficie de ataque, que NINGÚN perfil legítimo (legit.go) visita
// jamás. La ausencia total de superposición se comprueba en
// paths_test.go — no se da por sentada.
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

// FuzzParams es el conjunto de nombres de parámetro (nunca valores,
// según la regla de privacidad del contrato de eventos — ver
// docs/formato-eventos.md) que el escaneo lento agrega a algunos
// requests contra rutas válidas, simulando fuzzing de parámetros.
var FuzzParams = []string{"id", "debug", "admin", "token", "cmd", "redirect", "file"}
