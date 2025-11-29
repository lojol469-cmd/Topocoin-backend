# Dockerfile ← ce fichier doit s'appeler EXACTEMENT comme ça
FROM node:20-alpine

WORKDIR /app

# Copie package.json + package-lock.json
COPY package*.json ./

# Installe les dépendances (en prod)
RUN npm ci --only=production

# Copie tout le code
COPY . .

# Port exposé
EXPOSE 5000

# Démarrage
CMD ["node", "server.js"]