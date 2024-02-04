project-root/
│
├── controllers/
│   ├── authController.js
│   ├── userController.js
│   ├── propertyController.js
│   ├── leaseController.js
│   ├── fileController.js
│
├── middlewares/
│   ├── responseHandler.js
│   ├── authMiddleware.js
│
├── models/
│   ├── (所有 Sequelize 模型文件)
│
├── routes/
│   ├── authRoutes.js
│   ├── userRoutes.js
│   ├── propertyRoutes.js
│   ├── leaseRoutes.js
│   ├── fileRoutes.js
│
├── services/ (可选)
│   ├── authService.js
│   ├── userService.js
│   ├── propertyService.js
│
├── server.js
│
└── .env (环境变量文件)
