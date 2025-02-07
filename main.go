// main.go
package main

import (
	"fmt"
	_ "github.com/Nexzk/GBLOG/gin-swagger/docs" // 根据实际路径调整
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net/http"
	"os"
	"time"
)

// User 用户模型
type User struct {
	gorm.Model
	Username string `gorm:"unique"`
	Password string
}

// Article 文章模型
type Article struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `json:"title" binding:"required"`
	Content   string    `json:"content" binding:"required"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	db        *gorm.DB
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
)

func main() {
	// 初始化数据库
	dsn := "host=localhost user=postgres password=postgres dbname=blog port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("无法连接数据库")
	}
	db.AutoMigrate(&User{}, &Article{})

	// 初始化Gin
	r := gin.Default()

	// Swagger路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// 路由分组
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/login", login)
	}

	api := r.Group("/api")
	api.Use(JWTAuthMiddleware())
	{
		articles := api.Group("/articles")
		{
			articles.GET("", listArticles)
			articles.POST("", createArticle)
			articles.GET("/:id", getArticle)
			articles.PUT("/:id", updateArticle)
			articles.DELETE("/:id", deleteArticle)
		}
	}

	r.Run(":8080")
}

// @Summary 用户登录
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body User true "用户凭证"
// @Success 200 {string} string "JWT Token"
// @Router /auth/login [post]
func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 实际应用中需要验证用户名密码，这里简化为示例
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成Token失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// JWT鉴权中间件
func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未提供认证令牌"})
			return
		}

		tokenString = tokenString[len("Bearer "):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("非预期的签名方法: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user", claims["sub"])
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		}
	}
}

// 以下为文章相关处理函数
// @Summary 获取所有文章
// @Tags articles
// @Produce json
// @Success 200 {array} Article
// @Router /api/articles [get]
func listArticles(c *gin.Context) {
	var articles []Article
	db.Find(&articles)
	c.JSON(http.StatusOK, articles)
}

// @Summary 创建文章
// @Tags articles
// @Accept json
// @Produce json
// @Param article body Article true "文章内容"
// @Success 201 {object} Article
// @Router /api/articles [post]
func createArticle(c *gin.Context) {
	var article Article
	if err := c.ShouldBindJSON(&article); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result := db.Create(&article)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}

	c.JSON(http.StatusCreated, article)
}

// @Summary 获取单个文章
// @Tags articles
// @Produce json
// @Param id path int true "文章ID"
// @Success 200 {object} Article
// @Router /api/articles/{id} [get]
func getArticle(c *gin.Context) {
	var article Article
	if err := db.First(&article, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "文章不存在"})
		return
	}
	c.JSON(http.StatusOK, article)
}

// @Summary 更新文章
// @Tags articles
// @Accept json
// @Produce json
// @Param id path int true "文章ID"
// @Param article body Article true "更新内容"
// @Success 200 {object} Article
// @Router /api/articles/{id} [put]
func updateArticle(c *gin.Context) {
	var article Article
	if err := db.First(&article, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "文章不存在"})
		return
	}

	if err := c.ShouldBindJSON(&article); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.Save(&article)
	c.JSON(http.StatusOK, article)
}

// @Summary 删除文章
// @Tags articles
// @Param id path int true "文章ID"
// @Success 204
// @Router /api/articles/{id} [delete]
func deleteArticle(c *gin.Context) {
	if result := db.Delete(&Article{}, c.Param("id")); result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "文章不存在"})
		return
	}
	c.Status(http.StatusNoContent)
}
