const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const app = express();
const router = require('./router');
const mongoose = require('mongoose');
const config = require('./config');

//db setup

mongoose.connect('mongodb://'+config.dbuser+':'+config.dbpass+'@'+config.db);
//app setup

app.use(morgan('combined'));
app.use(bodyParser.json({type:'*/*'}));
router(app);

//server setup
const port = process.env.PORT || 3090;
const server = http.createServer(app);
server.listen(port);
