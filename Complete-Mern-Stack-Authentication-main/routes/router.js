const express = require("express");
const router = new express.Router();
const userdb = require("../models/userSchema");
var bcrypt = require("bcryptjs");
const authenticate = require("../middleware/authenticate");


// for user registration

// for user registration
router.post("/register", async (req, res) => {
    const { firstName, lastName, email, password, cpassword, dob, gender, contactNumber, address, emergencyContact, bloodGroup, allergies, medicalHistory } = req.body;

    if (!firstName || !lastName || !email || !password || !cpassword || !dob || !gender || !contactNumber || !address || !emergencyContact || !bloodGroup || !allergies || !medicalHistory) {
        res.status(422).json({ error: "fill all the details" });
        return; // Return to avoid sending multiple responses
    }

    try {
        const preuser = await userdb.findOne({ email: email });

        if (preuser) {
            res.status(422).json({ error: "This Email is Already Exist" });
            return; // Return to avoid sending multiple responses
        } else if (password !== cpassword) {
            res.status(422).json({ error: "Password and Confirm Password Not Match" });
            return; // Return to avoid sending multiple responses
        } else {
            const finalUser = new userdb({
                firstName,lastName, email, password, cpassword, dob, gender, contactNumber, address, emergencyContact, bloodGroup, allergies, medicalHistory
            });

            // here password hashing
            const storeData = await finalUser.save();

            res.status(201).json({ status: 201, storeData });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 500, error: "Internal Server Error" });
    }
});




// user Login

router.post("/login", async (req, res) => {
    // console.log(req.body);

    const { email, password } = req.body;

    if (!email || !password) {
        res.status(422).json({ error: "fill all the details" })
    }

    try {
       const userValid = await userdb.findOne({email:email});

        if(userValid){

            const isMatch = await bcrypt.compare(password,userValid.password);

            if(!isMatch){
                res.status(422).json({ error: "invalid details"})
            }else{

                // token generate
                const token = await userValid.generateAuthtoken();

                // cookiegenerate
                res.cookie("usercookie", token, {
                    expires: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)), // Set the expiration to one year from now
                    httpOnly: true
                });

                const result = {
                    userValid,
                    token
                }
                res.status(201).json({status:201,result})
            }
        }

    } catch (error) {
        res.status(401).json(error);
        console.log("catch block");
    }
});



// user valid
router.get("/validuser", authenticate, async (req, res) => {
    try {
        const ValidUserOne = await userdb.findOne({_id:req.userId});
        res.status(201).json({status:201,ValidUserOne});
    } catch (error) {
        // Handle the error here without sending a response from the middleware
        console.error(error);
        res.status(500).json({status:500, error: "Internal Server Error"});
    }
});

// user logout
router.get("/logout", authenticate, async (req, res) => {
    try {
        req.rootUser.tokens =  req.rootUser.tokens.filter((curelem)=>{
            return curelem.token !== req.token
        });

        res.clearCookie("usercookie",{path:"/"});

        req.rootUser.save();

        res.status(201).json({status:201})

    } catch (error) {
        // Handle the error here without sending a response from the middleware
        console.error(error);
        res.status(500).json({status:500, error: "Internal Server Error"});
    }
});





module.exports = router;



// 2 way connection
// 12345 ---> e#@$hagsjd
// e#@$hagsjd -->  12345

// hashing compare
// 1 way connection
// 1234 ->> e#@$hagsjd
// 1234->> (e#@$hagsjd,e#@$hagsjd)=> true



