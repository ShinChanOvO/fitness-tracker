FROM node:20

WORKDIR /app

# 先复制 package 文件
COPY package*.json ./

# 安装依赖
RUN npm install

# 复制其他文件
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
