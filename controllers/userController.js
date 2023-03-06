const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken, hashToken } = require("../utils/token");
var uaparser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const cryptr = new Cryptr(process.env.CRYPTR_KEY);
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);



//---------------------------Registration--------------------------------//

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({"message" : "Please fill all the required fields."});
  }
  // Check if user exists
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(400).json({"message" : "Email already in use."});
  }
    // Extracting User-Agent
    const ua = uaparser(req.headers["user-agent"]);
    const userAgent = [ua.ua];
    // Hashing Password
    const hashedPwd = await bcrypt.hash(password, 10);
    //create and store the new user
    const user = await User.create({
      name,
      email,
      password: hashedPwd,
      userAgent,
    })
    if(user){  
      // Generate Token
      const token = generateToken(user._id);
      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      })
      const { _id, name, email, bio, photo, role, isVerified, userAgent } = user;
      res.status(201).json({
        _id,
        name,
        email,
        bio,
        photo,
        role,
        isVerified,
        userAgent,
        token,
      });
    }
    else{
      res.status(400).json({"message" : "Invalid Details."});
    }
})



//---------------------------Login--------------------------------//

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  //   Validation
  if (!email || !password) {
    return res.status(400).json({"message" : "Please add email and password"});
  }
  let user = await User.findOne({ email : email });
  // Check if user exists
  if(!user){
    return res.json({ "message" : "User not registered." })
  }
  // Compare Password
  const passwordIsCorrect = await bcrypt.compare(password, user.password);
  if(passwordIsCorrect){
    // Extracting User-Agent
    const ua = uaparser(req.headers["user-agent"]);
    const newUserAgent = ua.ua;
    const allowedAgent = user.userAgent.includes(newUserAgent);    
    if(!allowedAgent){
      // Pushing new UserAgent in User-Agent field of user document
      await User.updateOne(
        { email : user.email },        
        { $push: { userAgent : newUserAgent } }            
      )
      // Generate 6 digit code
      const loginCode = Math.floor(100000 + Math.random() * 900000);
      console.log(loginCode);
      // Encrypt login code before saving to DB
      const encryptedLoginCode = cryptr.encrypt(loginCode.toString());
      // Delete Token if it exists in DB
      let userToken = await Token.findOne({ userId: user._id });
      if (userToken) {
        await userToken.deleteOne();
      }
      // Save Token to DB
      await new Token({
        userId: user._id,
        lToken: encryptedLoginCode,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (24 * 60 * 1000), // 1 day
      }).save();
      res.status(400).json({"message" :"New browser or device detected"});
    }
    // Generate Token
    const token = generateToken(user._id);
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    })
    const { _id, name, email, bio, photo, role, isVerified, userAgent } = user;
    res.status(200).json({
      _id,
      name,
      email,
      bio,
      photo,
      role,
      isVerified,
      userAgent,
      token,
    });
  } 
  else{
    return res.status(400).json({ "message" : "Password didn't match." })
  }
});



//---------------------------Send Login Code--------------------------------//

const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404).json({message : "User not found"});
  }
  // Find Login Code in DB
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404).json({message : "Invalid or Expired token, please login again"});
  }
  const loginCode = userToken.lToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);
  // Send Login Code
  const subject = "Login Access Code - AUTH:Z";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@titan.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;
  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: `Access code sent to ${email}` });
  } 
  catch (error) {
    res.status(500).json({message : "Email not sent, please try again"});
  }
});


//---------------------------Login with code--------------------------------//

const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404).json({message : "User not found"});
  }
  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404).json({message : "Invalid or Expired Token, please login again"});
  }
  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);
  if (loginCode !== decryptedLoginCode) {
    res.status(400).json({message : "Incorrect login code, please try again"});
  } 
  else {
    // Register userAgent
    const ua = uaparser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();
    // Generate Token
    const token = generateToken(user._id);
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });
    const { _id, name, email, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      name,
      email,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});



//---------------------------Send Verification Email--------------------------------//

const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404).json({message : "User not found"});
  }
  if (user.isVerified) {
    res.status(400).json({message : "User already verified"});
  }
  // Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }
  //   Create Verification Token and Save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
  }).save();
  // Construct Verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;
  // Send Email
  const subject = "Verify Your Account";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@titan.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;
  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Verification Email Sent" });
  } 
  catch (error) {
    res.status(500).json({message : "Email not sent, please try again"});
  }
});



//---------------------------Verify User--------------------------------//

const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  const hashedToken = hashToken(verificationToken);
  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404).json({message : "Invalid or Expired Token"});
  }
  // Find User
  const user = await User.findOne({ _id: userToken.userId });
  if (user.isVerified) {
    res.status(400).json({message : "User is already verified"});
  }
  // Now verify user
  user.isVerified = true;
  await user.save();
  res.status(200).json({ message: "Account Verification Successful" });
});



//---------------------------Logout--------------------------------//

const logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // 1 day
    sameSite: "none",
    secure: true,
  });
  res.status(200).json({ "message" : "Logout successful" });
});



//---------------------------Get User--------------------------------//

const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, bio, photo, role, isVerified } = user;
    res.status(200).json({
      _id,
      name,
      email,
      bio,
      photo,
      role,
      isVerified,
    });
  } 
  else {
    res.status(404).json({"message" : "User not found"});
  }
});

//---------------------------Update User--------------------------------//

const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { name, email, bio, photo, role, isVerified } = user;
    user.email = email;
    user.name = req.body.name || name;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } 
  else {
    res.status(404).json({"message" : "User not found"});
  }
});



//---------------------------Delete User--------------------------------//

const deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);
  if (!user) {
    res.status(404).json({"message" : "User not found"});
  }
  await user.remove();
  res.status(200).json({ message: "User deleted successfully"});
});



//---------------------------Get Users--------------------------------//

const getUsers = asyncHandler(async (req, res) => {
  // Get users list sorted according to creation time and deselected password.
  const users = await User.find().sort("-createdAt").select("-password");
  if (!users) {
    res.status(500).json({"message" : "Something went wrong"});
  }
  res.status(200).json(users);
});



//---------------------------Login Status--------------------------------//

const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  // Verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET_KEY);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});



//---------------------------Upgrade User--------------------------------//

const upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body;
  const user = await User.findById(id);
  if (!user) {
    res.status(404).json({"message" : "User not found"});
  }
  user.role = role;
  await user.save();
  res.status(200).json({ message: `User role updated to ${role}` });
});



//---------------------------Send Automated Email--------------------------------//

const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;
  if (!subject || !send_to || !reply_to || !template) {
    res.status(500).json({ message :"Missing email parameter"});
  }
  // Get user
  const user = await User.findOne({ email: send_to });
  if (!user) {
    res.status(404).json({"message" : "User not found"});
  }
  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONTEND_URL}${url}`;
  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Email Sent" });
  } 
  catch (error) {
    res.status(500).json({message : "Email not sent, please try again"});
  }
});



//---------------------------Forgot Password--------------------------------//

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    res.status(404).json({message : "No user with this email"});
  }
  // Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }
  //   Create Verification Token and Save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  // Hash token and save
  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
  }).save();

  // Construct Reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;
  // Send Email
  const subject = "Password Reset Request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@titan.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;
  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    res.status(200).json({ message: "Password Reset Email Sent" });
  } 
  catch (error) {
    res.status(500).json({message : "Email not sent, please try again"});
  }
});



//---------------------------Reset Password--------------------------------//

const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;
  const hashedToken = hashToken(resetToken);
  const userToken = await Token.findOne({
    rToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404).json({message : "Invalid or Expired Token"});
  }
  // Find User
  const user = await User.findOne({ _id: userToken.userId });
  // Hash Password
  const hashedPwd = await bcrypt.hash(password, 10);
  // Now Reset password
  user.password = hashedPwd;
  await user.save();
  res.status(200).json({ message: "Password Reset Successful, please login" });
});



//---------------------------Change Password--------------------------------//

const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);
  if (!user) {
    res.status(404).json({"message" : "User not found"});
  }
  if (!oldPassword || !password) {
    res.status(400).json({message : "Please enter old and new password"});
  }
  // Check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);
  // Save new password
  if (user && passwordIsCorrect) {
    // Hash Password
    const hashedPwd = await bcrypt.hash(password, 10);
    // Now Reset password
    user.password = hashedPwd;
    await user.save();
    res.status(200).json({ message: "Password change successful, please re-login" });
  } 
  else {
    res.status(400).json({message : "Old password is incorrect"});
  }
});



//--------------------------Google Sign-in--------------------------------//

const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;
  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];
  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    //   Create new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id);
      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });
      const { _id, name, email, bio, photo, role, isVerified } = newUser;
      res.status(201).json({
        _id,
        name,
        email,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    }
  }
  // User exists, login
  if (user) {
    const token = generateToken(user._id);
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });
    const { _id, name, email, bio, photo, role, isVerified } = user;
    res.status(201).json({
      _id,
      name,
      email,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
};
