const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const atob = require('atob');
const JWT = require('jsonwebtoken');
const users = [];

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use('/', express.static(__dirname));

const authenticateUSER = (req, res, next) => {
	const authHeader = req.headers.authorization;
	const token = authHeader && authHeader.split(' ')[1];
	if (token === null) return res.status(401).send();
	JWT.verify(token, 'supersecretKey', (err, user) => {
		req.user = err ? undefined : user;
		next();
	});
}

const badEmail = (email) => {
	return users.some(e => e.email === email);
}

const badPassword = (pw) => atob(pw).length < 6

const nameTaken = (username) => {
	const taken = users.some(e => (e.username === username));
	if (taken) return true;
	const alphaNum = /^[0-9a-zA-Z]+$/;
	if (!username.match(alphaNum)) return true;
	return false;
}

const createToken = (user) => JWT.sign(user, 'supersecretKey');

app.get('/api/sessions', authenticateUSER, (req, res) => {
	delete req.user.password;
	req.user === undefined ? res.json('NO') : res.json(req.user);
});

//use bcrypt.compare to compare hashed salt passwords
app.post('/api/login', async (req, res) => {
	const user = users.find(user => user.username === req.body.username);
	if (user === null) return res.status(400).send('cann0t find user');
	try {
		if (await bcrypt.compare(req.body.password, user.password)) {
			const accessToken = createToken(user);
			res.json({
				username: req.body.username,
				jwt: accessToken
			})
		} else {
			res.send('not allowed');
		}
	} catch {
		res.status(500).send();
	}
});

//creates new account
app.post('/api/signUp', async (req, res) => {
	try {
		const user = { ...req.body };
		if (badPassword(user.password)) return res.status(400).send('invalid password');
		if (badEmail(user.email)) return res.status(400).send('invalid email');
		if (nameTaken(user.username)) {
			return res.status(400).send('username already taken');
		}
		const hashedPassword = await bcrypt.hash(req.body.password, 3);
		user.password = hashedPassword;
		users.push(user);
		res.status(201);
		const accessToken = createToken(user);
		res.json({
			username: req.body.username,
			jwt: accessToken
		})
	} catch(err) {
		console.log(err)
		res.status(500).send();
	}
})

app.get('/', (req, res) => res.sendFile('index.html'));

app.listen(process.env.PORT || 8123);
