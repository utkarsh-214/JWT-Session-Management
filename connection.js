const mongoose = require("mongoose");
require("dotenv").config();

const connectionparams = {
    useNewUrlParser:true,
    useUnifiedTopology: true
};

const uri = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.pp8efut.mongodb.net/jwtService?retryWrites=true&w=majority`

const connection = mongoose.connect(uri, connectionparams).then(()=> console.log("connected to atlas"))
.catch((err)=>console.log(err)); 

module.exports = connection