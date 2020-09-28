package controllers

import (
	"../../utils"
	"../models"
	"../responses"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func (a *App) UserSignUp(w http.ResponseWriter, r *http.Request) {
	var resp = map[string]interface{}{"status": "succes", "message": "Registered successfully"}

	user := &models.User{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	usr, _ := user.GetUser(a.DB)
	if usr != nil {
		resp["status"] = "failed"
		resp["message"] = "User already registred, please login"
		responses.JSON(w, http.StatusBadRequest, resp)
		return
	}

	user.Prepare()

	err = user.Validate("")
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
	}
	userCreated, err := user.SaveUser(a.DB)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}
	resp["user"] = userCreated
	responses.JSON(w, http.StatusCreated, resp)
	return
}

func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	var resp = map[string]interface{}{"status": "success", "message": "logged in"}

	user := &models.User{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	user.Prepare()

	err = user.Validate("login")
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	usr, err := user.GetUser(a.DB)
	if err != nil {
		responses.ERROR(w, http.StatusInternalServerError, err)
		return
	}

	if usr == nil {
		resp["status"] = "failed"
		resp["message"] = "Login failed, please signup"
		responses.JSON(w, http.StatusBadRequest, err)
		return
	}

	err = models.CheckPasswordHash(user.Password, usr.Password)
	if err != nil {
		resp["status"] = "failed"
		resp["message"] = "Login failed, please try again"
		responses.JSON(w, http.StatusForbidden, resp)
		return
	}

	token, err := utils.EncodeAuthToken(usr.ID)
	if err != nil {
		responses.ERROR(w, http.StatusBadRequest, err)
		return
	}

	resp["token"] = token
	responses.JSON(w, http.StatusOK, resp)
}