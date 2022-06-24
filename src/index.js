const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const twofactor = require("node-2fa");

const authFactory = ({ library, sequelize, userModel, options }) => {

    let session = null;
    const getAuthUser = () => {
        return this.session?.authUser;
    }

    const setSession = (session) => {
        this.session = session;
    }

    const getSession = () => {
        return this.session;
    }

    class Session extends library.Model {

    }


    class AuthUser extends library.Model {

        async verifyPassword(password) {
            return await bcrypt.compare(password, this.User.password)
        }

        async login(sessionName) {
            //User and password are correct, now check if max sessions is reached
            await this.checkForSessions();
            this.lastLoginAt = new Date();
            let session = await this.createSession({ name: sessionName });
            await this.save();
            console.log(options)
            let token = jwt.sign(session.toJSON(), options.jwtSecret, { expiresIn: options.expiration })
            return { token, session };
        }

        async enable2FA() {
            if (this.confirmed2FA) {
                throw { message: "2FA is already enabled" }
            }
            let secret = twofactor.generateSecret({ name: options.appName, account: this.User.email });
            this.secret2FA = secret.secret;
            await this.save();
            return secret;
        }

        async disable2FA() {
            this.secret2FA = null;
            this.confirmed2FA = false;
            await this.save();
        }

        async checkForSessions() {
            if (options.maxSessionsPerUser == null){
                return;
            }
            let sessions = await Session.findAll({
                where: {
                    authUserId: this.id
                },
                order: [['createdAt', 'ASC']]
            })
            let sessionCount = sessions.length;
            if (options.invalidateOldestSession && sessionCount >= options.maxSessionsPerUser) {
                await sessions[0].destroy();
                sessionCount--;
            }
            if (sessions && sessionCount >= options.maxSessionsPerUser) {
                throw { message: "Max sessions reached, you need to logout in some other device" }
            }
        }

        async checkForMaxLoginAttempts() {

        }

        async confirm2FA(otp) {
            if (!this.secret2FA) {
                throw { message: "You need to enable 2fa before to confirm" }
            }

            if (this.confirmed2FA) {
                throw { message: "2FA is already enabled" }
            }
            this.verifyOTP(otp);
            this.confirmed2FA = true;
            await this.save();
        }

        verifyOTP(otp) {
            let verified = twofactor.verifyToken(this.secret2FA, otp, 2);
            if (!verified) {
                throw { message: "Invalid OTP" }
            }
            if (verified.delta < 0) {
                throw { message: "OTP is expired" }
            }
        }
    }

    AuthUser.init({
        id: { type: library.DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
        lastLoginAt: { type: library.DataTypes.DATE, defaultValue: library.DataTypes.NOW },
        secret2FA: { type: library.DataTypes.STRING },
        confirmed2FA: { type: library.DataTypes.BOOLEAN, defaultValue: false },
        userId: {
            type: library.DataTypes.INTEGER,
            references: {
                model: userModel,
                key: 'id'
            }
        }
    }, { sequelize, modelName: 'authUser' });

    Session.init({
        id: { type: library.DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
        authUserId: {
            type: library.DataTypes.INTEGER,
            references: {
                model: AuthUser,
                key: 'id'
            }
        },
        name: { type: library.DataTypes.STRING },
    }, { sequelize, modelName: 'session' });


    userModel.hasOne(AuthUser, { foreignKey: 'userId' });
    AuthUser.belongsTo(userModel, { foreignKey: 'userId' });
    AuthUser.hasMany(Session, { foreignKey: 'authUserId' });
    Session.belongsTo(AuthUser, { foreignKey: 'authUserId' });

    const middleware = async (req, res, next) => {
        let token = req.headers.token || req.headers.authorization

        if (token) {
            token = token.replace('Bearer ', '')
            const decoded = jwt.verify(token, options.jwtSecret)

            const session = await Session.findByPk(decoded.id, {
                include: {
                    model: AuthUser,
                    include: {
                        model: userModel
                    }
                }
            });
            if (session) {
                req.session = session
                req.authUser = session.authUser
                req.user = session.authUser.User;
                setSession(session);
            }
            else {
                throw { message: "The provided token is not assigned to any session", error_code: 401 }
            }
        }
        else {
            throw { message: "Token is not in the headers", error_code: 401 }
        }

        return next()
    }

    const authenticate = async (credentials) => {
        let user = await userModel.findOne({
            where: { email: credentials.email }
        })

        if (!user) {
            throw { message: "User not found" }
        }

        let authUser = await AuthUser.findOne({where: {userId: user.id}, include: {model: userModel}});
        if (!authUser){
            authUser = await AuthUser.create({userId: user.id})
            authUser = await AuthUser.findOne({where: {userId: user.id}, include: {model: userModel}});
        }

        //TODO: check for max login attempts and block user if too many attempts
        await authUser.checkForMaxLoginAttempts();

        if (!(await authUser.verifyPassword(credentials.password))) {
            throw { message: "Wrong password" }
        }

        //Check for 2FA
        if (authUser.confirmed2FA) {
            if (!credentials.otp) {
                throw { message: "2FA is enabled, you need to provide an OTP" }
            }
            await authUser.verifyOTP(credentials.otp);
        }


        return authUser;
    }

    const loginHandler = async (req, res) => {
        let { email, password, otp } = req.body;
        //Get AuthUser from credentials, this method will check if max_login_attempts is reached and if so, locks the user for a while
        let authUser = await authenticate({ email, password, otp });
        //User has been authenticated, create a session for the user
        let { token } = await authUser.login();
        let user = await authUser.getUser({ attributes: ['id', 'email'] });
        return res.json({ token, user });
    }

    const logoutHandler = async (req, res)=>{
        let {session} = req;
        await session.destroy()
        
        return res.status(200).json({
            message: "Session deleted successfully"
        });
    }

    const confirm2faHandler = async (req, res)=>{
        let {otp} = req.body;
        
        if(!otp){
            throw {message: "Missing OTP", error_code: 400}
        }
        let authUser = getAuthUser();
        await authUser.confirm2FA(otp);
        return res.status(200).json({message: "2FA is enabled"});
    }
    
    const enable2faHandler = async (req, res)=>{

        let {password} = req.body;
        
        if(!password){
            throw {message: "Missing password", error_code: 400}
        }
    
        let authUser = getAuthUser();
        if (!await authUser.verifyPassword(password)){
            throw {message: "Invalid password", error_code: 400}
        }
    
        let secret = await authUser.enable2FA(); 
    
        return res.status(200).json(secret);
    }
    
    const disable2FAHandler = async (req, res)=>{
        let {password} = req.body;
        if (!password){
            throw {message: "Missing password", error_code: 400}
        }
        let authUser = getAuthUser();
        if (!await authUser.verifyPassword(password)){
            throw {message: "Invalid password", error_code: 400}
        }
        await authUser.disable2FA();
        return res.status(200).json({message: "2FA is disabled"});
    }

    return {
        AuthUser,
        Session,
        middleware,
        authenticate,
        getAuthUser,
        getSession,
        loginHandler,
        logoutHandler,
        enable2faHandler,
        confirm2faHandler,
        disable2FAHandler
    }
}



module.exports.authFactory = authFactory