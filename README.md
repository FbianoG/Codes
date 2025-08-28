# ColaCode

#### 🧩 Geral

[🧪Api](#-api) - [🐳Docker](#-docker) - [🔑DotEnv](#-dotenv) - [📤Multer](#-multer) - [✏️Validate](#️-normalize--validação) - [🟨NodeTS](#-nodets) - [⚛️UseRouter](#️-userouter) - [🌐WebSocket](#-websocket) - [🔞Zod](#-zod)

#### 🔐 Security

[🔑Bcrypt](#-bcrypt) - [🌍Cors](#-cors) - [🍪Cookies](#-cookies) - [🔏Encrypt](#-encrypt) - [🚫Error](#-erros) - [🕐RateLimit](#-rate-limit)

#### ⚙️ Configurações

[✏️Commits](#️-commits) - [🎨Prettier](#-prettier) - [⚙️Vscode Config](#️-vscode-config) - [📟Logs](#-logs) - [🔼Prisma](#-prisma) - [⚛️Vite](#%EF%B8%8F-vite)

## Códigos

### 🧪 Api

Chamada de API pelo Frontend

1. Instalação

```bash
npm i axios
```

2. Crie uma pasta <b>api</b> e um arquivo dentro chamado <b>services.ts</b> e cole o código abaixo.

```ts
import { errorApi } from '@/utils/errorApi';
import Toast from '@/utils/Toast';
import axios from 'axios';

export const URL_BACK = 'http://localhost:3001';

const api = axios.create({
	baseURL: URL_BACK,
	withCredentials: true,
	headers: {
		'Content-Type': 'application/json',
	},
});

api.interceptors.request.use((config) => {
	const token = localStorage.getItem('token');
	if (token) {
		config.headers.Authorization = `Bearer ${token}`;
	}
	return config;
});


api.interceptors.response.use(
	(response) => response,
	(error) => {
		Toast('error', errorApi(error)), // foi configurado um Toast aqui
		return Promise.reject(error);
	}
);

export const userService = {
	login: async (data: { login: string; password: string }) => {
		const res = await api.post('/login', data);
		return res.data;
	},
};
```

3. Para usar, chame o <b>service</b> no componente.

```tsx
const { login } = userService;
```

4. Catch de erro (alterar se for usar function)

```ts
 catch (error: any) {
    if (error.response) {
        if (error.response.status === 401) {
            setTimeout(() => { location.href = '/' }, 4000);
        }
        if (error.response.status === 404) return error.message;
        throw new Error(error.response.data.message);
    } else if (error.request) {
        throw new Error("Erro de rede. Tente novamente.");
    } else {
        throw new Error(error.message);
    }
}
```

---

### 🐳 Docker

#### Intalação e uso


> [!NOTE]
>  O projeto precisa ter o dockerfile para criar imagem

```bash
# Vite
# Stage 1 - Build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build  # gera dist/

# Stage 2 - Production
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html


EXPOSE 80

## Express
FROM node:18-alpine

WORKDIR /app

COPY . .

RUN rm -rf node_modules
RUN npm i
RUN npx prisma generate
RUN npm run build

EXPOSE 4040

CMD ["npm", "start"]
```

1. Criar imagem
```bash
docker build -t NAME_IMAGEM .
```


> Caso queira exportar a `imagem` para um servidor (aws, azure...)

1.2. Criar um arquivo físico da imagem

```bash
docker save NAME_IMAGEM -o NAME_DO_ARQUIVO.tar
```

1.2. Enviar a imagem para o `servidor aws*`

```bash
scp -i keys_teste1.pem NAME_ARQUIVO ubuntu@SERVER_PUBLIC_IP:/home/ubuntu/
```

> A `key` é usada pela AWS para acesso via SSH

1.3 No `servidor aws*`, carregar a imagem no docker

```bash
docker load -i /home/usuario/clcode-image.tar
```

2. Criar network

> Caso queria linkar com outros conteiners na mesma network

```bash
docker network create --driver bridge NAME_NETWORK
```

3. Criar container

```bash
docker run -d --name NAME_CONTAINER --network NAME_NETWORK -e VARIABLE=TEXT -p PORT:PORT NAME_IMAGEM
```


#### Docker - Postgres

1. Criar imagem. (O código também cria o container junto)

```bash
docker run -d --name NOME_CONTAINER \
--network NAME_NETWORK \
-e POSTGRES_DB=NOME_DB \
-e POSTGRES_USER=USER_DB \
-e POSTGRES_PASSWORD=SENHA_DB \
-e TZ=America/Sao_Paulo \
-p 5432:5432 \
-v C:/pgdata:/var/lib/postgresql/data \
--restart unless-stopped \
postgres
```

> [-v] é onde o volume do banco de dados será armazenado. Caso queira persistir os dados, precisa ter.

2. Conectar ao backend

```ts
import { Pool } from 'pg';
const pool = new Pool({
	user: 'USER_DB',
	host: 'localhost', // ou nome do container se o backend estiver em Docker
	database: 'NAME_DB',
	password: 'PASSWORD_DB',
	port: 5432,
});
export default pool;

// --- Controller ---
const users = await pool.query('SELECT * FROM users');
res.status(200).json({ message: 'ok', data: users.rows });
```

3. Acessar Database

```bash
docker exec -it NAME_CONTAINER psql -U USER_DB -d NAME_DB
```

4. Comandos

```bash
# ver tabela
\dt
# ver colunas data tabela
\d
# sair do database
\q

### Deletar pgdata do Postgres --->
# windows (power shell)
Remove-Item -Path "CAMINHO_PASTA" -Recurse -Force

# windows (cmd)
rmdir /s /q CAMINHO_PASTA

# linux
sudo rm -rf ~/Área de Trabalho/pgdata
```

5. Importar e Exportar

> [!WARNING]
> Ao exportar, use o CMD para evitar erro de utf8
> Será exportado para a pasta ativa no terminal

```bash
# Importar database
docker exec -i NAME_CONTAINER psql -U USER_DB -d NAME_DB < backup.sql
# Exportar database (usar CMD para evitar erro utf8)
docker exec -i NAME_CONTAINER pg_dump -U USER_DB NAME_DB > backup.sql
```

#### Docker - Comandos Gerais

```bash
# Iniciar container
docker start <nome_container>

# Parar container
docker stop <nome_container>

# Ver containers ativos
docker ps

# Ver containers ativos e inativos
docker ps -a

# Ver logs
docker logs teste

# Ver logs em tempo real
docker logs -f <nome_container>

# Ver detalhes do container
docker inspect <nome_container>

# Deletar container
docker rm <nome_container>

### NETWORK ###

# Conectar container à network
docker network connect <name_network> <name_container>

# Ver networks
docker network ls

# Ver detalhes da network
docker network inspect <nome_network>

# Deletar network
docker network rm <nome_network>
```

---

### 🔑 DotEnv

1. Instalação

```bash
npm i dotenv
```

2. Criar arquivo `.env` na `root` do projeto

> [!WARNING]
> Não esquecer de incluir no `.gitignore`

```env
USERNAME_DATABASE="Fabiano123"
```

> Não é preciso importar o `dotenv` no `Next.js`, só use

```env
NEXT_PUBLIC_DATABASE="Fabiano123"
```

---

### 📤 Multer

1. Instalação

```bash
npm i multer
```

2. Crie um `middleware` com o nome `multer.ts` e cole o código abaixo

```ts
import { Request } from 'express';
import multer from 'multer';
import path from 'path';

// const storage = multer.memoryStorage(); // para armazenar o documento em memória e acessar o 'buffer' no controller

const storage = multer.diskStorage({
	// "storage" é como e aonde o documento será armazenado
	destination: (req: Request, file: Express.Multer.File, cb: any) => {
		cb(null, './img/'); // diretório parte do root até à pasta alvo (tem que criar a pasta antes para funcionar)
	},
	filename: (req: Request, file: Express.Multer.File, cb: any) => {
		cb(null, Date.now() + path.extname(file.originalname)); // cria o nome com a ISO atual e o formato do arquivo ".pdf .jpg .png etc."
	},
});

// Aqui verifica se o tipo do arquivo é aceitável
const fileFilter = (req: Request, file: Express.Multer.File, cb: any) => {
	const allowedFileTypes = /pdf|jpg|jpeg|png/;
	const extname = allowedFileTypes.test(path.extname(file.originalname).toLowerCase());
	const mimetype = allowedFileTypes.test(file.mimetype);

	if (extname && mimetype) {
		return cb(null, true);
	} else {
		cb('Erro: Tipos de arquivos permitidos são png, jpg, jpeg, gif, pdf, doc, docx, xls, xlsx, mp4, mp3!');
	}
};

// Ajusta o tamanho máximo do arquivo permitido
const limits = {
	fileSize: 4 * 1024 * 1024, // 4 MB
};

const upload = multer({
	storage: storage,
	fileFilter: fileFilter,
	limits: limits,
});

export default upload;
```

3. `router.ts` - Exemplo de uso

```ts
import upload from '../middlewares/multer';
router.post('/createDocument', verifyToken, upload.array('myFile'), createDocument); // upload.single('myFile') se semmpre for 1 arquivo
```

4. `Controller` - Exemplo de uso

```ts
const files = req.files as Express.Multer.File[]; // recebe o array de arquivos

const base64 = files[0].buffer.toString('base64'); // transforma o buffer em base64

fs.writeFileSync('./text.txt', base64); // salva o base64 em um arquivo
```

5. `Frontend` - Exemplo de uso
    > [!WARNING]
    > É obrigatório enviar o arquivo como multipart/form-data.

```ts
const createDocument = async (data: { message: string; to: string; myFile: FileList | null }) => {
	const formData = new FormData();
	if (data.myFile && data.myFile.length > 0) {
		for (let i = 0; i < data.myFile.length; i++) {
			formData.append('myFile', data.myFile[i]);
		}
	}
	formData.append('message', data.message);
	formData.append('to', data.to);
	const res = await axios.patch(URL_BACK + '/createDocument', formData);
};
```

---

### ✏️ Normalize & Validação

Aqui se retira os acentos, til, ç, espaços e caracteres especiais.

```ts
// Converte a string para letras minúsculas
.toLowerCase()
// Normaliza para decompor caracteres acentuados (ex: "é" → "e" + acento)
.normalize('NFD')
// Remove os diacríticos (acentos, til, etc.)
.replace(/[̀-ͯ]/g, '')
// Substitui "ç" por "c"
.replace(/ç/g, 'c')
// Remove caracteres que não sejam letras, números ou espaços
.replace(/[^a-zA-Z0-9 ]/g, '')
// Remove espaços extras no início e no fim da string
.trim();
```

Verificar `nome`

```ts
const textValidator = (text) => {
	if (!text || typeof text !== 'string') {
		return 'É necessário fornecer um "text".';
	}

	if (text.length < 3) {
		return 'O "text" deve conter pelo menos 3 caracteres.';
	}

	return text
		.toLowerCase()
		.normalize('NFD')
		.replace(/[\u0300-\u036f]/g, '')
		.replace(/ç/g, 'c')
		.replace(/[^a-zA-Z0-9 ]/g, '')
		.trim();

	// Se quiser erro de texto com acento etc... deve tirar o normalizer a
	if (!/^[a-zA-Z0-9 ]+$/.test(text)) {
		return 'O "text" deve conter apenas letras sem acento ou números.';
	}
};
```

Validar `email`

```ts
if (email && typeof email === 'string') {
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	if (!emailRegex.test(email)) {
		return res.status(400).json({ message: 'Email inválido.' });
	}
}
```

---

### 🟨 NodeTS

1. Iniciar projeto

```bash
npm init
```

2. Instalar dependências

```bash
npm i express mongoose cors
```

3. Instalar dependencias TypeScript

```bash
npm i typescript ts-node @types/node @types/express nodemon dotenv -D
```

4. Crie um arquivo `tsconfig.json` na root do projeto.

```json
{
	"compilerOptions": {
		"target": "es2016",
		"module": "commonjs",
		"esModuleInterop": true,
		"forceConsistentCasingInFileNames": true,
		"strict": true,
		"skipLibCheck": true,
		"outDir": "./dist",
		"rootDir": "./src"
	}
}
```

5. Mude os scrips no package.json.

```bash
"scripts": {
   "build": "tsc",
   "start": "node dist/index.js",
   "dev": "nodemon src/index.ts"
},
```

6. Se for hospedar na vercel, crie um arquivo `vercel.json` na root do projeto.

```json
{
	"version": 2,
	"builds": [
		{
			"src": "src/index.ts",
			"use": "@vercel/node"
		}
	],
	"routes": [
		{
			"src": "/(.*)",
			"dest": "src/index.ts"
		}
	]
}
```

8. Banco de dados para teste

```ts
const res = await mongoose.connect('mongodb+srv://teste:<teste1>@cluster0.s1parrs.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0');
```

---

### ⚛️ UseRouter

#### Next.js

1. Importação

```tsx
import { useRouter, usePathname, useSearchParams, useParams } from 'next/navigation';
```

2. Uso

> useParams() é usado apenas no App Router (app/), não no (pages/).

```tsx
const router = useRouter();

router.push('/home'); // Redireciona para /home
router.replace('/home'); // Substitui a rota atual por /home
router.back(); // Volta para a rota anterior
router.forward(); // Avança para a próxima rota (se houver)

// Obter pathname atual
const pathname = usePathname(); // ex: '/home'

// Obter query params
const searchParams = useSearchParams();
const id = searchParams.get('id'); // ex: ?id=123

// Obeter params - Só funciona no '/pasta/[pasta]
const params = useParams();
const patientId = params.patientId; // já vem como string
```

#### React.js

1. Importação

```tsx
import { useNavigate, useLocation, useParams } from 'react-router-dom';
```

2. Uso

```tsx
// Redirecionamento
const navigate = useNavigate();
navigate('/home');

// Obter pathname atual
const location = useLocation();
console.log(location.pathname);

// Obter query params
const location = useLocation();
console.log(location.search);

// Obeter params
const params = useParams();
console.log(params.id);
```

---

---

### 🌐 WebSocket

Ver exemplo em: [ProClinic-Front](https://github.com/FbianoG/ProClinic-Front/blob/main/src/components/chat/Chat.tsx)
Ver exemplo em: [ProClinic-Back](https://github.com/FbianoG/ProClinic-Back/blob/main/src/utils/webSocket.ts)

#### Backend

1. Instalação

```bash
npm i ws
```

> Frontend não precisa de instalação

2. Crie um servidor `HTTP` no `index` do projeto

> Pode ser usado com o `Express`, ambos podem ser utilizados juntos

> Na chamada do `listen` o `HTTP` unifica os servidores

```ts
import http from 'http';
import express from 'express';

const app = express();
const server = http.createServer(app);

// Chamada da função que inicia o WebSocket
webs(server);

// Utilizar o "server" para unificar ambos servidores "express - HTTP"
server.listen(port, () => {
	console.log('Server running on port ' + port);
});
```

3. Crie a `função` que irá iniciar o `WebSocket`

```ts
import WebSocket from 'ws';
import { Server } from 'http';

interface CustomWebSocket extends WebSocket {
	login: string;
}

const initWss = async (server: Server) => {
	const wss = new WebSocket.Server({ server });
	const clients = new Map<string, CustomWebSocket>(); // Caso faça sessões individuais de usuários

	wss.on('connection', (ws: WebSocket) => {
		ws.on('message', async (message: WebSocket.RawData) => {});
		ws.on('close', (code, reason) => {});
		ws.on('error', (error) => {});
	});
};
```

4. on('message')

Onde escuta todas as informações trocadas

> `ws` é o computador que está enviando a informação

> Só recebe `string` ou `buffer`.

> Pode enviar qualquer informação, preferencialmente `JSON`

- Validar entrada de dados:

```ts
let data;
try {
	if (typeof message === 'string') {
		data = JSON.parse(message);
	} else if (message instanceof Buffer) {
		// Se for JSON enviado como buffer UTF-8:
		const jsonString = message.toString('utf-8');
		data = JSON.parse(jsonString);
		// Se for binário real (imagem/vídeo), trate separadamente e não faça parse
		// Por exemplo, pode enviar um type indicando binário
	} else {
		throw new Error('Tipo de mensagem desconhecido');
	}
} catch (error) {
	console.error('Falha ao analisar a mensagem JSON:', error);
	ws.send(JSON.stringify({ type: 'error', message: 'Formato de mensagem inválido.' }));
	return;
}
```

- Enviar para o remetente

```ts
ws.send(JSON.stringify(OBJECT_DATA));
```

- Fechar Conexão

```ts
ws.close(CODIGO_ERRO, JSON.stringify(OBJECT_DATA));
```

- Criar uma sessão individual do usuário:

> Tem que ficar dentro do `on('message')`, é onde toda informação é trocada

```ts
if (data.type === 'authenticate') {
	// Assumindo que queira criar uma sessão com dados personalizados
	// Cria valores personalizados para o "ws"
	const decoded = jwt.verify(token, secretKey) as JwtPayload;
	ws.userId = decoded._id;
	ws.login = decoded.login;
	// Cria um novo cliente com as informações do "ws"
	clients.set(ws.userId!!, ws); // (identificador, dados)
}
```

- Localizar Cliente:

```ts
clients.get(IDENTIFICADOR);
```

- Enviar mensagem para um Cliente:

```ts
clients.get(IDENTIFICADOR).send(OBJECT_JSON);
```

- Deletar Cliente:

```ts
clients.delete(IDENTIFICADOR);
```

- Fazer algo com todos os Clientes:

```ts
clients.forEach((client) => {
	if (client.readyState === WebSocket.OPEN) {
		client.send(OBJECT_JSON);
	}
});
```

#### Frontend

> Não precisa instalar nada no `frontend`. O navegador ja possui `WebSocket` por padrão

1. Criar um `ref` do `WebSocket`. Assim o `WebSocket` não fica mutável

```tsx
const socket = useRef<WebSocket | null>(null);
```

2. Configura de onde virá a conexão. Usar dentro do `useEffect`

> [!NOTE]
> Use `ws` se estiver rodando localmente e `wss` se estiver em produção

```tsx
useEffect(() => {
	socket.current = new WebSocket('ws://localhost:3000');

	// Aqui trata sempre que o cliente se conectar
	socket.current.onopen = () => {};

	// Aqui trata sempre que o cliente recebe uma informação
	socket.current.onmessage = (event) => {};

	// Aqui trata sempre que o cliente recebe um erro
	socket.current.onerror = (err) => {};

	// Aqui trata sempre que o cliente fechar a conexão
	socket.current.onclose = () => {};

	return () => {
		socket.current?.close();
	};
}, []);
```

3. Enviar mensagem

> Pode usar em qualquer lugar desde que tenha importado o `ref SocketWeb`

```tsx
socket.current.send(JSON.stringify(OBJECT));
```

---

### 🔞 Zod

#### Backend

1. Instalação

```bash
npm i zod
```

2. Importação

```ts
import z from 'zod';

z.config(z.locales.pt()); // é para configurar o idioma da resposta padrão de erro
```

3. Criar `Schema`

```ts
const loginSchema = z
	.object({
		login: z.string().trim().min(3).max(15),
		password: z.string().trim().min(3).max(20),
	})
	.refine((data) => data.login !== '123', { message: 'O login não pode ser "123"', path: ['login'] });

const { login, password } = loginSchema.parse(req.body);
```

> [!NOTE]
> O erro de uma validação cai direto no `catch` e é pego pelo [Middleware de Erro](#-erros)

#### Frontend

1. Instalação

```bash
npm install zod @hookform/resolvers react-hook-form
```

2. Criar `Schema`
3. Exportar a `typagem` do `formulário` para uso do `submit`

```ts
export type loginFormData = z.infer<typeof loginSchema>;
```

4. Importar `Schemas` no componente

```tsx
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { loginFormData, loginSchema } from '@/schemas/schemas';
```

6. Configurar a chamada do `react-hook-form` no `componente`

```tsx
const {
	register,
	handleSubmit,
	formState: { errors },
} = useForm({
	resolver: zodResolver(loginSchema),
});
```

7. Modo de uso

```tsx
const handleLogin = (data: loginFormData) => {
	login(data);
}

return (
	<form onSubimit={handleSubmit(handleLogin}>
		<Input id='login' {...register('login')} />
		<Input id='password' type='password' {...register('password')} />
	</form>
)
```

---

## Seguraça

### 🔑 Bcrypt

Hash para criptografar senhas

1. Instalação

```bash
npm i bcrypt
```

2. Criar um hash

```ts
import bcrypt from 'bcrypt';

export const hashPassword = async (password) => {
	try {
		const salt = await bcrypt.genSalt(10); // aleatoriza mais ainda os "salt"
		const hash = await bcrypt.hash(password, salt); // cria o hash - (senhaDigitada, salt)
		return hash;
	} catch (error) {
		throw error;
	}
};
```

3. Comparar hash com senha digitada (senhaDigitada, senhaHashed)

```ts
export const comparePassword = async (plainPassword, hashedPassword) => {
	try {
		const match = await bcrypt.compare(plainPassword, hashedPassword); // compara a senha (senhaDigitada, senhaNoDataBase)
		return match;
	} catch (error) {
		throw error;
	}
};
```

---

### 🌍 Cors

1. Instalação

```bash
npm i cors
```

2. Cole o código no <b>index.js</b>.

> app.use(cors) - deve ser usado antes das rotas

```ts
import cors from 'cors';

const corsOptions = {
	origin: 'http://127.0.0.1:5500', // Permite acesso apenas do domínio específico
	methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Métodos HTTP permitidos
	credentials: true, // Permite o envio de cookies e headers de autenticação
	optionsSuccessStatus: 204, // Status de sucesso para requisições OPTIONS
	exposedHeaders: 'Authorization', // Expõe o header 'Authorization' para o cliente
};

// Configura o CORS com as opções definidas
app.use(cors(corsOptions));
```

---

### 🍪 Cookies

> [!NOTE]
> Ao usar o frontend em domínio diferente do backend, pode haver problemas de permissão de `cookies de terceiros`

1. Instalação

```bash
npm i cookie-parser
```

2. Cole o código no `index.ts`

```ts
import cookieParser from 'cookie-parser';

// Permitir somente HTTPS
app.use((req, res, next) => {
	if (req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https') {
		return next();
	}
	res.status(403).json({ error: 'Apenas HTTPS permitido.' });
});

// Permitir proxy (ex: heroku, vercel etc)
app.set('trust proxy', true);

// Ler cookies
app.use(cookieParser());
```

3. Colar o código abaixo no `controller de login` para enviar o cookie na response

```ts
res.cookie('token', token, {
	httpOnly: true, // não pode ser acessado pelo javascript
	secure: process.env.DEV_MODE ? false : true, // TRUE para aceitar apenas https
	sameSite: 'none', // pode ser acessado de qualquer origem - 'strict' se for o mesmo domínio
	maxAge: 3 * 3600000, // expira em 3 horas
});
```

> Se o domínio do backend for diferente do frontend, use `sameSite: 'none'`. Se for igual, pode usar `sameSite: 'lax'`

---

### 🔏 Encrypt

> [!NOTE]
> Não precisa instalar nada. Já é nativo do Node.js

1. Modo de uso

```ts
import crypto from 'crypto';
import 'dotenv/config';

const createKey = crypto.randomBytes(32); // aqui é para criar a key. Deve ser criada uma única vez e ser salva. (se perder, nao consegue reverter a criptografia)

const key = Buffer.from(process.env.CRYPTO_KEY!, 'base64');

export const encrypt = (text: string) => {
	const iv = crypto.randomBytes(12); // nonce único por criptografia
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

	const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
	const tag = cipher.getAuthTag();

	return {
		iv: iv.toString('base64'),
		tag: tag.toString('base64'),
		content: encrypted.toString('base64'),
	};
};

export const decrypt = (encrypted: { iv: string; tag: string; content: string }) => {
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'base64'));

	decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));

	const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted.content, 'base64')), decipher.final()]);

	return decrypted.toString('utf8');
};
```

---

### 🚫 Erros

1. Crie uma `classe`

```ts
export class ErroApi extends Error {
	constructor(
		public statusCode: number,
		message: string,
	) {
		super(message);
		this.statusCode = statusCode;
	}
}

export default ErroApi;
```

2. Criar o middleware de erro no `index.js`

```ts
// ! Criar depois de tudo e antes do `listen`
app.use((error: any, req: Request, res: Response, next: NextFunction) => {
	if (error instanceof ErroApi) {
		res.status(error.statusCode).json({ message: error.message });
	} else if (error instanceof z.ZodError) {
		// aqui se se for usar com "zod"
		res.status(400).json({ message: `${error.issues[0].path}: ${error.issues[0].message}` });
	} else {
		console.error(error);
		res.status(500).json({ message: 'Erro interno de servidor' });
	}
});
```

3. Incluir o `(next: NextFunction)` no `controller`

4. Usar a `classe` para chamar algum erro dentro do `try`

```ts
if (value > 2) throw new ApiError(400, 'Valor é maior que 2');
```

5. No `catch` use o apenas o

```ts
catch (error) {
   next(error)
}
```

---

### 🕐 Rate Limit

1. Instalação

```bash
npm i express-rate-limit
```

2. Crie um `middleware`

```ts
import rateLimit from 'express-rate-limit';

const rateLimiter = rateLimit({
	windowMs: 3 * 60 * 1000, // 3 minutos
	max: 5, // máx. 5 tentativas por IP
	handler: (req, res) => {
		return res.status(429).json({
			success: false,
			message: 'Muitas tentativas de acesso. Tente novamente em alguns minutos.',
		});
	},
});

export default rateLimiter;
```

3. Use na `route` que queira aplicar

```ts
router.post('/login', rateLimiter, controller);
```

---

## Configurações

### ✏️ Commits

```bash
feat: (feature) - para novas funcionalidades.

fix: (fix) - para correção de bugs.

docs: (docs) - para mudanças na documentação.

style: (style) - para formatação, semicolons ausentes, etc. (sem mudança no código).

refactor: (refactor) - para refatoração de código (sem mudança no comportamento).

test: (test) - para adição ou correção de testes.

build: (build) - para mudanças que afetam o sistema de build ou dependências externas.

ci: (ci) - para mudanças nos arquivos de configuração e scripts de CI.

perf: (performance) - para melhorias de performance.

chore: (chore) - outras mudanças que não afetam o código fonte ou testes (ex: atualização de dependências menores).
```

---

### 🎨 Prettier

1. Instalação

```bash
npm i -D prettier prettier-plugin-tailwindcss
```

2. Crie um arquivo `.prettierrc` dentro da pasta `root` do projeto.

```json
{
	"semi": true,
	"singleQuote": true,
	"jsxSingleQuote": true,
	"trailingComma": "all",
	"printWidth": 190,
	"tabWidth": 4,
	"useTabs": true,
	"arrowParens": "always",
	"bracketSameLine": true,
	"bracketSpacing": true,
	"plugins": ["prettier-plugin-tailwindcss"]
}
```

---

### ⚙️ Vscode Config

1. No VScode aperte `ctrl+shift+p` e digite `user settings`.

2. Apos abrir o arquivo `settings.json`, cole código abaixo:

```json
{
	// 🖋️ Formatadores por linguagem
	"[html]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[javascript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[typescript]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[typescriptreact]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[jsonc]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[json]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	"[css]": { "editor.defaultFormatter": "esbenp.prettier-vscode" },
	// 🎨 Tema e aparência
	"workbench.iconTheme": "material-icon-theme", // Tema de ícones
	"explorer.compactFolders": false, // Pastas compactadas
	"breadcrumbs.enabled": false, // Desativa breadcrumbs
	// 💾 Salvamento automático
	"files.autoSave": "afterDelay", // Salva após inatividade
	"files.autoSaveDelay": 200, // Delay de 200ms
	// ⚙️ Editor
	"editor.guides.bracketPairs": true, // Guia de colchetes
	"editor.bracketPairColorization.independentColorPoolPerBracketType": true, // Cor independente por tipo
	"editor.cursorSmoothCaretAnimation": "off", // Animação do cursor
	"editor.cursorBlinking": "blink", // Cursor piscando
	"editor.renderWhitespace": "none", // Não mostra espaços/tabs
	"editor.minimap.enabled": false, // Desativa o minimapa
	"editor.snippetSuggestions": "top", // Sugestão de snippets no topo
	"editor.wordWrap": "on", // Quebra de linha automática
	"editor.tabSize": 3, // Tamanho do tab

	// "editor.rulers": [80], // Define uma margem visual na coluna 80
	// "editor.wordWrapColumn": 80, // Define a coluna de quebra de linha

	// 🧠 CodeLens e assistentes
	"codeium.enableCodeLens": false, // Desativa CodeLens do Codeium
	// ✨ Prettier
	"prettier.semi": true, // Usa ponto e vírgula
	"prettier.singleQuote": true, // Aspas simples
	"prettier.jsxSingleQuote": true, // Aspas simples em JSX
	"prettier.trailingComma": "all", // Vírgulas finais
	"prettier.printWidth": 180, // Largura máxima
	"prettier.tabWidth": 2, // Tamanho do tab
	"prettier.useTabs": true, // Usa tabs
	"prettier.arrowParens": "always", // Parênteses em arrow functions
	"prettier.bracketSameLine": true, // Colchete JSX na mesma linha
	"prettier.bracketSpacing": true, // Espaço entre chaves
	// 🔁 Importações automáticas
	"typescript.updateImportsOnFileMove.enabled": "always", // TS
	"javascript.updateImportsOnFileMove.enabled": "always", // JS
	"editor.formatOnSave": true, // Formata ao salvar
	"editor.codeActionsOnSave": {
		"source.organizeImports": "always" // organiza os imports automaticamente
	},
	// 👨‍💻 Terminal
	"terminal.integrated.cursorBlinking": true, // Cursor piscando
	"terminal.integrated.cursorStyle": "line", // Cursor em linha
	"terminal.integrated.cursorWidth": 2,
	"editor.stickyScroll.enabled": false,
	"git.enableSmartCommit": true,
	"git.confirmSync": false,
	"tailwind-fold.unfoldIfLineSelected": true,
	"tailwind-fold.foldedText": "ClassName",
	"tailwind-fold.showTailwindImage": false,
	"vscodeGoogleTranslate.preferredLanguage": "English",
	"workbench.layoutControl.enabled": false,
	"workbench.navigationControl.enabled": false,
	"window.commandCenter": false,
	"workbench.startupEditor": "none",
	"workbench.tree.indent": 15, // Indentação das pastas na barra lateral
	"workbench.editor.empty.hint": "hidden",
	"editor.inlineSuggest.edits.renderSideBySide": "never",
	"editor.inlineSuggest.edits.allowCodeShifting": "never",
	"github.copilot.enable": {
		"*": false,
		"plaintext": false,
		"markdown": false,
		"scminput": false,
		"typescriptreact": false
	},
	"js-auto-backticks.enableRevert": true,
	"explorer.confirmDragAndDrop": false

	// 🖋️ Fontes
	// "editor.fontFamily": "Consolas, 'Courier New', monospace", // Fonte
	// "editor.fontWeight": "300", // Peso da fonte
	// "editor.fontSize": 14, // Tamanho da fonte
	// "editor.lineHeight": 1.5, // Altura da linha
	// "editor.fontLigatures": true // Liga as ligaturas
}
```

---

### 📟 Logs

Aparecer bara de loading no log do cmd

```bash
process.stdout.write(`Processando: ${index + 1}/${find.length}\r`);

const progress = Math.floor(((index + 1) / find.length) * 50);
process.stdout.write(`.[${'='.repeat(progress)}${'.'.repeat(50 - progress)}] ${index + 1}/${find.length}\r`);
```

---

### 🔼 Prisma

1. Instalação
```bash
npm install prisma --save-dev
npm install @prisma/client
```
2. Iniciar o prisma
```bash
npx prisma init
```
3. No `root`, criar a pasta `prisma` com o arquivo `schema.prisma`

4. Configurar conforme [Prisma Models](https://www.prisma.io/docs/orm/prisma-schema/data-model/models)

5. Criar `src/libs/prisma.ts`

```ts
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
export default prisma;
```
6. Usar o `migrate` ou `generate`
> `migrate` sincroniza o DB com o schema
```bash
npx prisma generate
npx prisma migrate dev
```
  
---

### ⚛️ Vite

#### Configurar portas

1. Incluir o código dentro do `defineConfig` em `vite.config.ts`

```bash
preview: {
   port: 3000,
},
server: {
	port: 3000,
},
```

#### Usar rotas

1. Instalar

```bash
npm i react-router-dom
```

2. No arquivo `main.tsx`

```tsx
import { BrowserRouter, Route, Routes } from 'react-router-dom';
<StrictMode>
   <BrowserRouter>
      <Routes>
         <Route path='/' element={<Login />} />
         <Route path='/user' element={<User />} />
      </Routes>
   </BrowserRouter>
</StrictMode>,
```

> Se usar algum layout específico para páginas privadas

```tsx
<Route path='/' element={<Login />} />
<Route element={<PrivateProvider />}>
	<Route path='/user' element={<User />} />
	<Route path='/settings' element={<Settings />} />
</Route>
```

#### Hospedar na Vercel

1. Criar o arquivo `vercel.json`

```json
{
	"$schema": "https://openapi.vercel.sh/vercel.json",
	"rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
```

### 🎨 CSS

#### Sections
```css
@main md:px-8 lg:px-16 xl:px-36 max-w-7xl
@section py-16 md:py-24
@title mb-16 max-w-2xl 
@title:title text-3xl mb-4
@content gap-8
```






