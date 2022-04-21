<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //Request data from the db table
        $requestData = $request->all();
        //Validate it
        $validator = Validator::make($requestData,[
            'name' => 'required|max:55',
            'email' => 'email|required|unique:users',
            'password' => 'required|confirmed'
        ]);

        //If this fails return a 422, something didn't go well
        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        //If it does work, has the password to store in the DB
        $requestData['password'] = Hash::make($requestData['password']);

        //create a user
        $user = User::create($requestData);

        //return success message to the endpoint
        return response([ 'status' => true, 'message' => 'User successfully register.' ], 200);
    }

    public function login(Request $request)
    {
        //request information about login
        $requestData = $request->all();

        //validate
        $validator = Validator::make($requestData,[
            'email' => 'email|required',
            'password' => 'required'
        ]);

        //If fails, return 422 error
        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors()
            ], 422);
        }

        //if not logged in, deny access
        if(! auth()->attempt($requestData)){
            return response()->json(['error' => 'UnAuthorised Access'], 401);
        }

        //If login correct, create an access token
        $accessToken = auth()->user()->createToken('authToken')->accessToken;

        //return user info/token
        return response(['user' => auth()->user(), 'access_token' => $accessToken], 200);
    }

    public function me(Request $request)
    {
        //Checks which user
        $user = $request->user();

        return response()->json(['user' => $user], 200);
    }

    public function logout (Request $request)
    {
        //grabs user token
        $token = $request->user()->token();
        //deletes token
        $token->revoke();
        //Logs user out
        $response = ['message' => 'You have been successfully logged out!'];
        //Returns success message
        return response($response, 200);
    }
}
