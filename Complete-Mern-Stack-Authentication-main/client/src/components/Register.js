import React, { useState, useContext } from 'react';
import { NavLink } from "react-router-dom";
import {LoginContext} from "./ContextProvider/Context";
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import "./mix.css"

const Register = () => {
    const { setLoginData } = useContext(LoginContext);

    const [passShow, setPassShow] = useState(false);
    const [cpassShow, setCPassShow] = useState(false);

    const [inpval, setInpval] = useState({
        firstName: "",
        lastName: "",
        email: "",
        password: "",
        cpassword: "",
        dob: "",
        gender: "",
        contactNumber: "",
        address: "",
        emergencyContact: "",
        bloodGroup: "",
        allergies: "",
        medicalHistory: "",
    });

    const [errors, setErrors] = useState({});

    const setVal = (e) => {
        const { name, value } = e.target;

        setInpval((prevData) => ({
            ...prevData,
            [name]: value
        }));
    };

    const addUserdata = async (e) => {
        e.preventDefault();

        const {
            firstName,
            lastName,
            email,
            password,
            cpassword,
            dob,
            gender,
            contactNumber,
            address,
            emergencyContact,
            bloodGroup,
            allergies,
            medicalHistory
        } = inpval;

        // Validation checks
        const validationErrors = {};

        if (firstName === "") {
            toast.warning("First name is required!", {
                position: "top-center"
            });
        } else if (lastName === "") {
            toast.warning("Last name is required!", {
                position: "top-center"
            });
        } else if (email === "") {
            toast.error("Email is required!", {
                position: "top-center"
            });
        } else if (!email.includes("@")) {
            toast.warning("Include @ in your email!", {
                position: "top-center"
            });
        } else if (password === "") {
            toast.error("Password is required!", {
                position: "top-center"
            });
        } else if (password.length < 6) {
            toast.error("Password must be at least 6 characters!", {
                position: "top-center"
            });
        } else if (cpassword === "") {
            toast.error("Confirm password is required!", {
                position: "top-center"
            });
        } else if (cpassword.length < 6) {
            toast.error("Confirm password must be at least 6 characters!", {
                position: "top-center"
            });
        } else if (password !== cpassword) {
            toast.error("Password and Confirm password do not match!", {
                position: "top-center"
            });
        } else if (dob === "") {
            toast.error("Date of Birth is required!", {
                position: "top-center"
            });
        } else if (gender === "") {
            toast.error("Gender is required!", {
                position: "top-center"
            });
        } else if (contactNumber === "") {
            toast.error("Contact Number is required!", {
                position: "top-center"
            });
        } else if (address === "") {
            toast.error("Address is required!", {
                position: "top-center"
            });
        } else if (emergencyContact === "") {
            toast.error("Emergency Contact is required!", {
                position: "top-center"
            });
        } else if (bloodGroup === "") {
            toast.error("Blood Group is required!", {
                position: "top-center"
            });
        } else if (allergies === "") {
            toast.error("Allergies are required!", {
                position: "top-center"
            });
        } else if (medicalHistory === "") {
            toast.error("Medical History is required!", {
                position: "top-center"
            });
    

        } else {
            // Proceed with API call and success handling
            const data = await fetch("/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    firstName,
                    lastName,
                    email,
                    password,
                    cpassword,
                    dob,
                    gender,
                    contactNumber,
                    address,
                    emergencyContact,
                    bloodGroup,
                    allergies,
                    medicalHistory
                })
            });

            const res = await data.json();
            console.log(res);

            if (res.status === 201) {
                toast.success("Registration Successfully done 😃!", {
                    position: "top-center"
                });
                setLoginData({ ValidUserOne: res.user }); 
                setInpval({
                    firstName: "",
                    lastName: "",
                    email: "",
                    password: "",
                    cpassword: "",
                    dob: "",
                    gender: "",
                    contactNumber: "",
                    address: "",
                    emergencyContact: "",
                    bloodGroup: "",
                    allergies: "",
                    medicalHistory: "",
                });
                setErrors({});
            }
        }
    }

    return (
        <section>
            <div className="form_data">
                <div className="form_heading">
                    <h1>Sign Up</h1>
                    <p style={{ textAlign: "center" }}>We are glad that you will be using Project Cloud to manage <br />
                        your tasks! We hope that you will get like it.</p>
                </div>

                <form>
                    <div className="form_input">
                        <label htmlFor="firstName">First Name</label>
                        <input type="text" onChange={setVal} value={inpval.firstName} name="firstName" id="firstName" placeholder='Enter Your First Name' />
                        <span>{errors.firstName}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="lastName">Last Name</label>
                        <input type="text" onChange={setVal} value={inpval.lastName} name="lastName" id="lastName" placeholder='Enter Your Last Name' />
                        <span>{errors.lastName}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="email">Email</label>
                        <input type="email" onChange={setVal} value={inpval.email} name="email" id="email" placeholder='Enter Your Email Address' />
                        <span>{errors.email}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="password">Password</label>
                        <div className="two">
                            <input type={!passShow ? "password" : "text"} value={inpval.password} onChange={setVal} name="password" id="password" placeholder='Enter Your password' />
                            <div className="showpass" onClick={() => setPassShow(!passShow)}>
                                {!passShow ? "Show" : "Hide"}
                            </div>
                        </div>
                        <span>{errors.password}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="cpassword">Confirm Password</label>
                        <div className="two">
                            <input type={!cpassShow ? "password" : "text"} value={inpval.cpassword} onChange={setVal} name="cpassword" id="cpassword" placeholder='Confirm password' />
                            <div className="showpass" onClick={() => setCPassShow(!cpassShow)}>
                                {!cpassShow ? "Show" : "Hide"}
                            </div>
                        </div>
                        <span>{errors.cpassword}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="dob">Date of Birth</label>
                        <input type="date" onChange={setVal} value={inpval.dob} name="dob" id="dob" />
                        <span>{errors.dob}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="gender">Gender</label>
                        <select onChange={setVal} value={inpval.gender} name="gender" id="gender">
                            <option value="">Select Gender</option>
                            <option value="male">Male</option>
                            <option value="female">Female</option>
                            <option value="other">Other</option>
                        </select>
                        <span>{errors.gender}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="contactNumber">Contact Number</label>
                        <input type="tel" onChange={setVal} value={inpval.contactNumber} name="contactNumber" id="contactNumber" placeholder='Enter Your Contact Number' />
                        <span>{errors.contactNumber}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="address">Address</label>
                        <input type="text" onChange={setVal} value={inpval.address} name="address" id="address" placeholder='Enter Your Address' />
                        <span>{errors.address}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="emergencyContact">Emergency Contact</label>
                        <input type="tel" onChange={setVal} value={inpval.emergencyContact} name="emergencyContact" id="emergencyContact" placeholder='Enter Emergency Contact' />
                        <span>{errors.emergencyContact}</span>
                    </div>
                    
                    <div className="form_input">
                        <label htmlFor="bloodGroup">Blood Group</label>
                        <select onChange={setVal} value={inpval.bloodGroup} name="bloodGroup" id="bloodGroup">
                            <option value="">Select Blood Group</option>
                            <option value="a+">A+</option>
                            <option value="o+">O+</option>
                            <option value="b+">B+</option>
                            <option value="ab+">AB+</option>
                            <option value="a-">A-</option>
                            <option value="o-">O-</option>
                            <option value="b-">B-</option>
                            <option value="ab-">AB-</option>
                        </select>
                        <span>{errors.bloodGroup}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="allergies">Allergies</label>
                        <input type="text" onChange={setVal} value={inpval.allergies} name="allergies" id="allergies" placeholder='Enter Any Known Allergies' />
                        <span>{errors.allergies}</span>
                    </div>
                    <div className="form_input">
                        <label htmlFor="medicalHistory">Medical History</label>
                        <textarea onChange={setVal} value={inpval.medicalHistory} name="medicalHistory" id="medicalHistory" placeholder='Enter Medical History' />
                        <span>{errors.medicalHistory}</span>
                    </div>
                    <button className='btn' onClick={addUserdata}>Sign Up</button>
                    <p>Already have an account? <NavLink to="/">Log In</NavLink></p>
                </form>
                <ToastContainer />
            </div>
        </section>
    )
}

export default Register