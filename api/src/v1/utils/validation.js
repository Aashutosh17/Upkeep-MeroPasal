export const validateEmail = (email) => {
	return String(email)
		.toLowerCase()
		.match(
			/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
		)
}


export const validatePassword = (password) => {
	// Define password strength criteria
	const hasUpperCase = /[A-Z]/.test(password);
	const hasLowerCase = /[a-z]/.test(password);
	const hasNumber = /[0-9]/.test(password);
	const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
	const isLengthValid = password.length >= 8 && password.length <= 12;
	const isStrongPassword = hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar && isLengthValid;

	return {
		isStrongPassword,
		hasUpperCase,
		hasLowerCase,
		hasNumber,
		hasSpecialChar,
		isLengthValid
	};
};


export const validateUsername = (username) => {
	return String(username).match(/^[a-zA-Z0-9]+([_ -]?[a-zA-Z0-9])*$/)
}

export const validateName = (name) => {
	return String(name).match(/^[A-Z][a-zA-Z]{3,}(?: [A-Z][a-zA-Z]*){0,2}$/)
}
