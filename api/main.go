package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

// --- GLOBAL VARIABLES ---
var db *pgxpool.Pool
var jwtSecret []byte

// --- MODELS ---
type JwtCustomClaims struct {
	UID  string `json:"uid"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type TransactionDetail struct {
	ID      string                   `json:"id"`
	Total   float64                  `json:"total"`
	Method  string                   `json:"method"`
	Date    time.Time                `json:"date"`
	Cashier string                   `json:"cashier"`
	Items   []map[string]interface{} `json:"items"`
}

// --- MAIN FUNCTION ---
func main() {
	// 1. Load Environment & Secret
	if err := godotenv.Load(); err != nil {
		log.Println("Peringatan: File .env tidak ditemukan, menggunakan ENV sistem")
	}

	secretString := os.Getenv("JWT_SECRET")
	if secretString == "" {
		log.Fatal("Error: JWT_SECRET harus diatur di dalam environment!")
	}
	jwtSecret = []byte(secretString)

	// 2. Initialize Database (Optimized for Supabase)
	connStr := os.Getenv("DB_CONN")
	var err error
	db, err = initDB(connStr)
	if err != nil {
		log.Fatalf("Gagal koneksi database: %v", err)
	}

	e := echo.New()

	// 3. Middlewares
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization}, // WAJIB ADA INI
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
	}))

	// --- PUBLIC ROUTES ---
	e.POST("/login", handleLogin)

	// --- RESTRICTED ROUTES (JWT Protected) ---
	r := e.Group("")
	r.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: jwtSecret,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(JwtCustomClaims)
		},
	}))

	// Basic Protected Routes
	r.GET("/products", getProducts)
	r.GET("/transactions", getTransactions)
	r.POST("/checkout", handleCheckout)

	// Admin Only Routes
	r.POST("/register", handleRegister, isAdmin)
	r.POST("/products", createProduct, isAdmin)
	r.PUT("/products/:id", updateProduct, isAdmin)
	r.DELETE("/products/:id", deleteProduct, isAdmin)

	// 4. Start Server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	e.Logger.Fatal(e.Start(":" + port))
}

// --- DATABASE HELPER ---
func initDB(connStr string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}

	// SOLUSI UNTUK SUPABASE: Gunakan Simple Protocol agar tidak error Prepared Statement
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.MaxConns = 10
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return pool, pool.Ping(context.Background())
}

// --- MIDDLEWARE: ADMIN CHECK ---
func isAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*JwtCustomClaims)
		if claims.Role != "admin" {
			return c.JSON(http.StatusForbidden, map[string]interface{}{
				"message":     "Akses ditolak! Hanya Paduka Admin yang berkuasa.",
				"result_code": 403,
			})
		}
		return next(c)
	}
}

// --- HANDLERS ---

func handleLogin(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	c.Bind(&req)

	var id, fullName, role, hashedPass string
	query := `SELECT id, full_name, role, password FROM profiles_bansu WHERE email=$1`
	err := db.QueryRow(context.Background(), query, req.Email).Scan(&id, &fullName, &role, &hashedPass)

	if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPass), []byte(req.Password)) != nil {
		return c.JSON(401, map[string]interface{}{
			"message":     "Email atau Password Salah",
			"result_code": 401,
		})
	}

	claims := &JwtCustomClaims{
		UID:  id,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 168)), // 7 Hari
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, _ := token.SignedString(jwtSecret)

	return c.JSON(200, map[string]interface{}{
		"message":     "Selamat Datang Paduka!",
		"result_code": 200,
		"data": map[string]interface{}{
			"token": t, "role": role, "full_name": fullName, "user_id": id,
		},
	})
}

func handleRegister(c echo.Context) error {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
	}
	c.Bind(&req)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	query := `INSERT INTO profiles_bansu (email, password, full_name, role) VALUES ($1, $2, $3, $4)`
	_, err := db.Exec(context.Background(), query, req.Email, string(hashed), req.FullName, req.Role)

	if err != nil {
		return c.JSON(500, map[string]interface{}{"message": err.Error(), "result_code": 500})
	}
	return c.JSON(201, map[string]interface{}{"message": "Registrasi Berhasil", "result_code": 201})
}

func getProducts(c echo.Context) error {
	rows, _ := db.Query(context.Background(), "SELECT id, name, price, stock, image_url FROM products_bansu")
	defer rows.Close()

	var products []map[string]interface{}
	for rows.Next() {
		var id, name, img string
		var price float64
		var stock int
		rows.Scan(&id, &name, &price, &stock, &img)
		products = append(products, map[string]interface{}{
			"id": id, "name": name, "price": price, "stock": stock, "image_url": img,
		})
	}
	return c.JSON(200, map[string]interface{}{"message": "Sukses", "result_code": 200, "data": products})
}

func createProduct(c echo.Context) error {
	var req struct {
		Name     string  `json:"name"`
		Price    float64 `json:"price"`
		Stock    int     `json:"stock"`
		ImageUrl string  `json:"image_url"`
	}
	c.Bind(&req)
	_, err := db.Exec(context.Background(), "INSERT INTO products_bansu (name, price, stock, image_url) VALUES ($1, $2, $3, $4)", req.Name, req.Price, req.Stock, req.ImageUrl)
	if err != nil {
		return c.JSON(500, map[string]interface{}{"message": err.Error(), "result_code": 500})
	}
	return c.JSON(201, map[string]interface{}{"message": "Produk ditambahkan", "result_code": 201})
}

func updateProduct(c echo.Context) error {
	id := c.Param("id")
	var req struct {
		Name     string  `json:"name"`
		Price    float64 `json:"price"`
		Stock    int     `json:"stock"`
		ImageUrl string  `json:"image_url"`
	}
	c.Bind(&req)
	query := `UPDATE products_bansu SET name=$1, price=$2, stock=$3, image_url=$4 WHERE id=$5`
	_, err := db.Exec(context.Background(), query, req.Name, req.Price, req.Stock, req.ImageUrl, id)
	if err != nil {
		return c.JSON(500, err.Error())
	}
	return c.JSON(200, map[string]interface{}{"message": "Produk diupdate", "result_code": 200})
}

func deleteProduct(c echo.Context) error {
	id := c.Param("id")
	_, err := db.Exec(context.Background(), "DELETE FROM products_bansu WHERE id=$1", id)
	if err != nil {
		return c.JSON(500, err.Error())
	}
	return c.JSON(200, map[string]interface{}{"message": "Produk dihapus", "result_code": 200})
}

func handleCheckout(c echo.Context) error {
	var req struct {
		UserID string  `json:"user_id"`
		Total  float64 `json:"total"`
		Method string  `json:"method"`
		Items  []struct {
			ProductID string  `json:"product_id"`
			Qty       int     `json:"qty"`
			Subtotal  float64 `json:"subtotal"`
		} `json:"items"`
	}
	c.Bind(&req)

	tx, _ := db.Begin(context.Background())
	defer tx.Rollback(context.Background())

	var transID string
	err := tx.QueryRow(context.Background(),
		"INSERT INTO transactions_bansu (user_id, total_price, payment_method) VALUES ($1, $2, $3) RETURNING id",
		req.UserID, req.Total, req.Method).Scan(&transID)

	if err != nil {
		return c.JSON(500, err.Error())
	}

	for _, item := range req.Items {
		tx.Exec(context.Background(), "INSERT INTO transaction_items_bansu (transaction_id, product_id, quantity, subtotal) VALUES ($1, $2, $3, $4)", transID, item.ProductID, item.Qty, item.Subtotal)
		tx.Exec(context.Background(), "UPDATE products_bansu SET stock = stock - $1 WHERE id = $2", item.Qty, item.ProductID)
	}

	tx.Commit(context.Background())
	return c.JSON(200, map[string]interface{}{
		"message":     "Checkout Berhasil",
		"result_code": 200,
		"data":        map[string]string{"id": transID},
	})
}

func getTransactions(c echo.Context) error {
	idParam := c.QueryParam("id")
	startDate := c.QueryParam("start_date")
	endDate := c.QueryParam("end_date")

	query := `
		SELECT t.id, t.total_price, t.payment_method, t.created_at, p.full_name, ti.quantity, ti.subtotal, pr.name
		FROM transactions_bansu t
		LEFT JOIN profiles_bansu p ON t.user_id = p.id
		LEFT JOIN transaction_items_bansu ti ON t.id = ti.transaction_id
		LEFT JOIN products_bansu pr ON ti.product_id = pr.id
		WHERE 1=1`

	var args []interface{}
	argCount := 1

	if idParam != "" {
		query += fmt.Sprintf(" AND t.id = $%d", argCount)
		args = append(args, idParam)
		argCount++
	}
	if startDate != "" && endDate != "" {
		query += fmt.Sprintf(" AND t.created_at >= $%d AND t.created_at <= $%d", argCount, argCount+1)
		args = append(args, startDate+" 00:00:00", endDate+" 23:59:59")
		argCount += 2
	}
	query += " ORDER BY t.created_at DESC"

	rows, err := db.Query(context.Background(), query, args...)
	if err != nil {
		return c.JSON(500, err.Error())
	}
	defer rows.Close()

	transactions := make(map[string]*TransactionDetail)
	var order []string

	for rows.Next() {
		var id, method, cashier, prodName string
		var total, subtotal float64
		var date time.Time
		var qty int
		rows.Scan(&id, &total, &method, &date, &cashier, &qty, &subtotal, &prodName)

		if _, exists := transactions[id]; !exists {
			transactions[id] = &TransactionDetail{ID: id, Total: total, Method: method, Date: date, Cashier: cashier, Items: []map[string]interface{}{}}
			order = append(order, id)
		}
		if prodName != "" {
			transactions[id].Items = append(transactions[id].Items, map[string]interface{}{"product_name": prodName, "qty": qty, "subtotal": subtotal})
		}
	}

	var result []*TransactionDetail
	for _, id := range order {
		result = append(result, transactions[id])
	}

	return c.JSON(200, map[string]interface{}{"message": "Sukses", "result_code": 200, "data": result})
}
