const dotenv = require("dotenv");
dotenv.config();
const connectDB = require('./connect/connectDB');
connectDB();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleware/errorMiddleware");

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://melodic-hotteok-e34598.netlify.app"],
  credentials: true,
}));

// Routes
app.use("/api/users", userRoute);

// Error Handler
app.use(errorHandler);

const PORT = process.env.PORT || 9000;
app.listen(PORT, (err)=>{
  if(err){
    console.log(err);
  }
  else{
    console.log(`Server created at port ${PORT}.`)
  }
})
