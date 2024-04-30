<?php

namespace App\Http\Controllers;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;


class AuthController extends Controller
{
    public function user(Request $request){
        $user = $request->user();
        return response()->json([
            'user' => $user,
            'message' => 'User retrieved successfully'
        ]);
    }

    public function register(Request $request){
        $fields = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'confirmed'],
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
        ]);

        $token = $user->createToken('RegistrationToken')->plainTextToken;

        return response()->json([
            'user' => $user,
            'token' => $token,
            'message' => 'Registered successfully'

        ], 201);
    }

    public function login(Request $request){

        try{

            $credentials = $request->validate([
                'email' => ['required','email'],
                'password' => ['required'],
            ]);
    
    
            if(Auth::attempt($credentials)){
    
                $user = Auth::user();
                $token = $user->createToken('LoginToken')->plainTextToken;
    
                return response()->json([
                    'user' => $user,
                    'token' => $token,
                    'message' => 'Loggedin successfully'

                ],201);
    
            }

        }catch(\Exception $e){
            return response()->json(['message' => 'The provided credentials are incorrect.'], 500);

        }
       

    }

    public function logout() {
        auth()->user()->tokens()->delete();
        return response()->json([
            'message' => 'Logged out Successfully'
        ]);
    }

}
