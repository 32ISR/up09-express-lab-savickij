const express = require("express")
const db = require("./db")
const app = express()
const bcr = require('bcryptjs')
const jwt = require('jsonwebtoken')
app.use(express.json())
const PORT = 3000
const SECRET = "123321123"


app.post("/api/auth/register", (req, res) => {
    try {
        console.log(req.body);
        const { username, password, email } = req.body

        if (!username || !password) {
            return res.status(400).json({ error: "." })
        }

        if (username.length < 3) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "Недостаточно символов в пароле" })
        }

        const existing = db.prepare(
            "SELECT id FROM users WHERE username = ?"
        ).get(username)

        if (existing) return res.status(409).json({ error: "Пользователь уже существует" })

        const salt = bcr.genSaltSync(10)
        const hash = bcr.hashSync(password, salt)
        const role = "user"

        const info = db.prepare(`INSERT INTO users (username, email, password, role)
            VALUES(?,?,?,?)`).run(username.trim(), email.trim(), hash, role)

        const newUser = db.prepare(`SELECT * FROM users WHERE id = ?`).get(info.lastInsertRowid)

        const { password: _, ...safeUser } = newUser

        const token = jwt.sign({ ...safeUser }, SECRET, { expiresIn: "24h" })
        res.status(201).json({ success: true, token, user: safeUser })
    } catch (err) {
        console.error(err)
        return res.status(500).json({ error: "Failed to create" })
    }
})

app.post("/api/auth/login", (req, res) => {
    try {
        const { username, password } = req.body
        if (!username || !password) {
            return res.status(400).json({ error: "Missing data" })
        }

        const user = db.prepare(
            "SELECT * FROM users WHERE username = ?"
        ).get(username)
        if (!user) {
            return res.status(400).json({ error: "Пользователя нету" })
        }

        const valid = bcr.compareSync(password, user.password)
        if (!valid) return res.status(400).json({ error: "Пароль невереный" })

        const { password: _, ...safeUser } = user
        const token = jwt.sign({ ...safeUser }, SECRET, { expiresIn: "24h" })
        res.status(200).json({ success: true, token, user: safeUser })
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Something wrong" })
    }
})
app.get("/api/auth/profile", (req, res) => {
    try {
        const user = db.prepare(
            "SELECT * FROM users WHERE id = ?"
        ).get(req.user.id)
        const{password, ...safeUser} = user
        return res.status(200).jason(safeUser)
    } catch (error) {
        console.error(error)
        return res.status(500).json({ error: "Something wrong" })
    }
})

app.post("/auth/books", (req,res)=>{
    try {
        const{ title,author,year,genre,description } = req.body

        if (!title||!title) {
            return res
            .status(400)
            .json({error:"Нужно название"})
        }

        if(!author||!author){
            return res.status(400).json({error:"Нужен автор"})
        }

        if(!year||!year){
            return res.status(400).json({error:"Нужен год"})
        }

        if(!genre||!genre){
            return res.status(400).json({error:"Нужен жанр"})
        }

        if(!description||!description){
            return res.status(400).json({error:"Нужно описание"})
        }

        const info = db.prepare(`
            INSERT INTO books ( title,author,year,genre,description ,createdBy)
            VALUES(?,?,?,?,?,?)
            `).run(title.trim(),author.trim(),Number(year), genre.trim(),description.trim(),req.user.id
        )

        const newBooks = db
        .prepare(`SELECT * FROM books WHERE id = ?`)
        .get(info.lastInsertRowid)

        const {password: _, ...safeUser} = newUser

         return res.status(201).json(newBooks)
    } catch (err) {
        console.error(err)
        return res.status(500).json({error:"Failed to fetch"})
    }
})

app.get("/api/books", (req, res) => {
    try {
        const books = db.prepare(
            "SELECT * FROM books"
        ).all()
         return res.status(201).json(books)
    } catch (err) {
        console.error(err)
        return res.status(500).json({error:"Failed to fetch"})
    }
})

app.listen(PORT)