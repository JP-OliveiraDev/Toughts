const { where } = require('sequelize')
const User = require('../models/User')

const bcrypt = require('bcryptjs')

module.exports = class AuthController {

    static login (req, res) {
        res.render('auth/login')
    }

    static async loginPost(req, res) {
        const {email, password} = req.body

        // Usuario existe
        const user = await User.findOne({ where: { email: email } })

        if(!user) {
            req.flash('message', 'Usuário não encontrado, tente novamente!')
            res.render('auth/login')

            return
        }

        // verificar a senha
        const passwordMatch = bcrypt.compareSync(password, user.password)

        if(!passwordMatch) {
            req.flash('message', 'Senha inválida, tente novamente!')
            res.render('auth/login')

            return
        }

        // Inicializar a seção
        req.session.userid = user.id
            
        req.flash('message', 'Autenticação realizada com sucesso!')

        req.session.save(() => {
            res.redirect('/')
        })

    }

    static register (req, res) {
        res.render('auth/register')
    }

    static async resgisterPost(req, res) {

        const { name, email, password, confirmpassword } = req.body

        // password validação
        if(password != confirmpassword) {
            req.flash('message', 'As senhas não conferem, tente novamente!')
            res.render('auth/register')

            return
        }

        //Check se o uusuario existe
        const checkIfUserExists =  await User.findOne({where: {email:email}})

        if(checkIfUserExists) {
            req.flash('message', 'O e-mail já está em uso, tente novamente!')
            res.render('auth/register')

            return
        }

        //Criar a senha
        const salt = bcrypt.genSaltSync(10)
        const hashedPassword = bcrypt.hashSync(password, salt)

        const user = {
            name,
            email,
            password: hashedPassword
        }

        try {
            const createdUser = await User.create(user)

            // Inicializar a seção
            req.session.userid = createdUser.id
            
            req.flash('message', 'Cadastro realizado com sucesso!')

            req.session.save(() => {
                res.redirect('/')
            })
        } catch(err) {
            console.log(err)
        }
        

    }

    static logout(req, res) {
        req.session.destroy()
        res.redirect('/login')
    }
}

