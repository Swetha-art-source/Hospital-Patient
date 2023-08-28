import React, { createContext, useState } from 'react'

export const LoginContext = createContext({
    logindata: { ValidUserOne: null }, // Initial value indicating no user
    setLoginData: () => {} // Just a placeholder function, the actual function will be provided by useState
});

const Context = ({ children }) => {
    const [logindata, setLoginData] = useState({ ValidUserOne: null }); // Initial value indicating no user

    return (
        <LoginContext.Provider value={{ logindata, setLoginData }}>
            {children}
        </LoginContext.Provider>
    );
}

export default Context;