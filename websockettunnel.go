package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v2"
)

// Структура для чтения конфигурации из YAML
type Config struct {
	Mode          string `yaml:"mode"` // режим работы (server или client)
	Authorization struct {
		Password string `yaml:"password"` // пароль для авторизации
	} `yaml:"authorization"`
	Server struct {
		Address string `yaml:"address"` // адрес сервера
		Path    string `yaml:"path"`    // путь для WebSocket
	} `yaml:"server"`
	TunInterface string `yaml:"tun_interface"` // имя TUN интерфейса
}

// Функция для загрузки конфигурации из файла YAML
func loadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Разрешаем все подключения
}

// Мьютекс для защиты WebSocket соединения от конкурентных записей
var wsWriteMutex sync.Mutex

// Структура для пакетов данных
type packet struct {
	data []byte
	size int
}

// Серверная часть
func runServer(config *Config) {
	iface, mtu, err := openTunInterfaceDirectly(config.TunInterface) // Подключаемся к указанному интерфейсу
	if err != nil {
		log.Fatal("Ошибка подключения к TUN интерфейсу на сервере:", err)
	}

	log.Printf("Подключение к серверному TUN интерфейсу: %s с MTU %d.", config.TunInterface, mtu)

	http.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		handleConnection(w, r, iface, mtu, config)
	}) // Обрабатываем только путь /vpn
	log.Println("Сервер запущен на порту 8080...")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}

// Обработка WebSocket соединений на сервере с проверкой пароля
func handleConnection(w http.ResponseWriter, r *http.Request, iface *os.File, mtu int, config *Config) {
	password := r.Header.Get("Authorization")
	if password != "Bearer "+config.Authorization.Password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка апгрейда до WebSocket:", err)
		return
	}
	defer conn.Close()

	packetChan := make(chan packet, 100) // Канал для буферизации данных
	defer close(packetChan)

	go pingConnection(conn)

	// Асинхронное чтение из TUN и запись в WebSocket
	go readFromTun(iface, mtu, packetChan)
	go sendToWebSocket(conn, packetChan)

	// Асинхронное чтение из WebSocket и запись в TUN
	readFromWSAndWriteToTun(iface, conn)
}

// Периодическая отправка ping
func pingConnection(conn *websocket.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		wsWriteMutex.Lock()
		err := conn.WriteMessage(websocket.PingMessage, nil)
		wsWriteMutex.Unlock()
		if err != nil {
			log.Println("Ошибка отправки ping:", err)
			return
		}
	}
}

// Открытие существующего TUN интерфейса напрямую через os.OpenFile
func openTunInterfaceDirectly(ifaceName string) (*os.File, int, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0600)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка открытия /dev/net/tun: %v", err)
	}

	// Привязка к существующему интерфейсу ifaceName
	var ifr [18]byte
	copy(ifr[:15], ifaceName)
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_TUN | syscall.IFF_NO_PI

	// Привязываем интерфейс через системный вызов ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(0x400454ca), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return nil, 0, fmt.Errorf("ошибка привязки интерфейса %s: %v", ifaceName, errno)
	}

	// Получаем MTU интерфейса
	mtu, err := getMTU(ifaceName)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка получения MTU для интерфейса %s: %v", ifaceName, err)
	}

	log.Printf("Подключён к интерфейсу %s с MTU %d", ifaceName, mtu)
	return file, mtu, nil
}

// Получение MTU интерфейса
func getMTU(ifaceName string) (int, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("ошибка получения информации об интерфейсе %s: %v", ifaceName, err)
	}
	return iface.MTU, nil
}

// Асинхронное чтение из TUN и отправка данных через канал
func readFromTun(iface *os.File, mtu int, ch chan packet) {
	for {
		buffer := make([]byte, mtu)
		n, err := iface.Read(buffer)
		if err != nil {
			log.Println("Ошибка чтения из TUN интерфейса:", err)
			break
		}
		ch <- packet{data: buffer[:n], size: n}
	}
	close(ch)
}

// Асинхронная отправка данных в WebSocket
func sendToWebSocket(conn *websocket.Conn, ch chan packet) {
	for p := range ch {
		wsWriteMutex.Lock()
		err := conn.WriteMessage(websocket.BinaryMessage, p.data)
		wsWriteMutex.Unlock()
		if err != nil {
			log.Println("Ошибка отправки сообщения по WebSocket:", err)
			break
		}
	}
}

// Чтение данных из WebSocket и запись в TUN интерфейс
func readFromWSAndWriteToTun(iface *os.File, conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Ошибка чтения из WebSocket:", err)
			break
		}

		_, err = iface.Write(message)
		if err != nil {
			log.Println("Ошибка записи в TUN интерфейс:", err)
			break
		}
	}
}

// Клиентская часть
func runClient(config *Config) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u := url.URL{Scheme: "wss", Host: config.Server.Address, Path: config.Server.Path}
	log.Printf("Подключение к серверу: %s", u.String())

	header := http.Header{}
	header.Set("Authorization", "Bearer "+config.Authorization.Password)

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Fatal("Ошибка подключения:", err)
	}
	defer conn.Close()

	iface, mtu, err := openTunInterfaceDirectly(config.TunInterface) // Подключаемся к TUN интерфейсу клиента
	if err != nil {
		log.Fatal("Ошибка подключения к TUN интерфейсу на клиенте:", err)
	}

	log.Printf("Подключен к клиентскому TUN интерфейсу: %s с MTU %d.", config.TunInterface, mtu)

	packetChan := make(chan packet, 100) // Канал для буферизации данных
	defer close(packetChan)

	go pingConnection(conn)

	// Асинхронное чтение из TUN и запись в WebSocket
	go readFromTun(iface, mtu, packetChan)
	go sendToWebSocket(conn, packetChan)

	// Асинхронное чтение из WebSocket и запись в TUN
	readFromWSAndWriteToTun(iface, conn)
}

// Главная функция для запуска в режиме клиента или сервера
func main() {
	configFile := flag.String("config", "config.yaml", "Путь к файлу конфигурации")
	flag.Parse()

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	switch config.Mode {
	case "server":
		fmt.Println("Запуск в режиме сервера")
		runServer(config)
	case "client":
		fmt.Println("Запуск в режиме клиента")
		runClient(config)
	default:
		fmt.Println("Неизвестный режим:", config.Mode)
		fmt.Println("Использование: -mode=server или -mode=client")
	}
}
