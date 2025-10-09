<?php

declare(strict_types=1);

use App\Http\Controllers\CommentController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\UserController;
use App\Models\Category;
use App\Models\Tag;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', static fn (Request $request) => $request->user());

// Public API routes
Route::get('/posts', [PostController::class, 'index']);
Route::get('/posts/{post:slug}', [PostController::class, 'show']);
Route::get('/categories', static fn () => Category::active()->get());
Route::get('/tags', static fn () => Tag::active()->get());

// Protected API routes
Route::middleware('auth:sanctum')->group(static function (): void {
    // User profile
    Route::get('/profile', static fn (Request $request) => $request->user()->load('profile'));
    Route::put('/profile', [UserController::class, 'updateProfile']);

    // Comments
    Route::post('/posts/{post}/comments', [CommentController::class, 'store']);
    Route::put('/comments/{comment}', [CommentController::class, 'update']);
    Route::delete('/comments/{comment}', [CommentController::class, 'destroy']);
});

// Admin API routes
Route::middleware(['auth:sanctum', 'role:admin'])->group(static function (): void {
    Route::get('/admin/users', [UserController::class, 'index']);
    Route::post('/admin/users', [UserController::class, 'store']);
    Route::get('/admin/users/{user}', [UserController::class, 'show']);
    Route::put('/admin/users/{user}', [UserController::class, 'update']);
    Route::delete('/admin/users/{user}', [UserController::class, 'destroy']);

    Route::get('/admin/comments/moderation', [CommentController::class, 'moderation']);
    Route::patch('/admin/comments/{comment}/approve', [CommentController::class, 'approve']);
    Route::patch('/admin/comments/{comment}/reject', [CommentController::class, 'reject']);
});

// Editor API routes
Route::middleware(['auth:sanctum', 'role:admin,editor'])->group(static function (): void {
    Route::get('/admin/posts', [PostController::class, 'index']);
    Route::post('/admin/posts', [PostController::class, 'store']);
    Route::get('/admin/posts/{post}/edit', [PostController::class, 'edit']);
    Route::put('/admin/posts/{post}', [PostController::class, 'update']);
    Route::delete('/admin/posts/{post}', [PostController::class, 'destroy']);
    Route::patch('/admin/posts/{post}/toggle-featured', [PostController::class, 'toggleFeatured']);
});
