const mongoose = require('mongoose');

mongoose.set('strictQuery', true);

const connectDB = async() => {
    try{
        mongoose.connect(process.env.MONGO_URL)
    }
    catch(err){
        return console.log(err);
    }
}
module.exports = connectDB;