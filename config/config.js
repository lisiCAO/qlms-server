require("dotenv").config(); // 确保在文件顶部引入 dotenv

module.exports = {
    development: {
        username: "root",
        password: "password",
        database: "qlmsdb",
        host: "qlms-db",
        dialect: "mysql",
    },
    test: {
        username: "test_user",
        password: "test_pass",
        database: "test_db",
        host: "127.0.0.1",
        dialect: "mysql",
    },
    production: {
        username: process.env.PROD_DB_USERNAME, // 使用环境变量
        password: process.env.PROD_DB_PASSWORD,
        database: process.env.PROD_DB_NAME,
        host: process.env.PROD_DB_HOST,
        dialect: "mysql",
        // 使用 SSL 和其他生产环境推荐的设置
        dialectOptions: {
            ssl: {
                require: true,
                rejectUnauthorized: false,
            },
        },
    },
};
