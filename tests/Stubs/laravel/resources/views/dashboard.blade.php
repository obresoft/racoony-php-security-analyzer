<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard - {{ config('app.name', 'Laravel') }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url('/') }}">{{ config('app.name', 'Laravel') }}</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ route('posts.index') }}">Posts</a>
                    </li>
                    @if(auth()->user()->role === 'admin')
                        <li class="nav-item">
                            <a class="nav-link" href="{{ route('admin.users.index') }}">Users</a>
                        </li>
                    @endif
                    @if(in_array(auth()->user()->role, ['admin', 'editor']))
                        <li class="nav-item">
                            <a class="nav-link" href="{{ route('admin.posts.index') }}">Manage Posts</a>
                        </li>
                    @endif
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            {{ Auth::user()->name }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ route('profile.show') }}">Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <form method="POST" action="{{ route('logout') }}">
                                    @csrf
                                    <button type="submit" class="dropdown-item">Logout</button>
                                </form>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1>Dashboard</h1>
                <p class="lead">Welcome back, {{ Auth::user()->name }}!</p>
            </div>
        </div>

        <div class="row">
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title">Your Posts</h5>
                        <p class="card-text display-6">{{ Auth::user()->posts()->count() }}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title">Your Comments</h5>
                        <p class="card-text display-6">{{ Auth::user()->comments()->count() }}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title">Published Posts</h5>
                        <p class="card-text display-6">{{ Auth::user()->posts()->published()->count() }}</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h5 class="card-title">Draft Posts</h5>
                        <p class="card-text display-6">{{ Auth::user()->posts()->where('status', 'draft')->count() }}</p>
                    </div>
                </div>
            </div>
        </div>

        @if(in_array(auth()->user()->role, ['admin', 'editor']))
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Quick Actions</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <a href="{{ route('admin.posts.create') }}" class="btn btn-primary w-100 mb-2">
                                    Create New Post
                                </a>
                            </div>
                            @if(auth()->user()->role === 'admin')
                            <div class="col-md-4">
                                <a href="{{ route('admin.users.create') }}" class="btn btn-success w-100 mb-2">
                                    Create New User
                                </a>
                            </div>
                            <div class="col-md-4">
                                <a href="{{ route('admin.comments.moderation') }}" class="btn btn-warning w-100 mb-2">
                                    Moderate Comments
                                </a>
                            </div>
                            @endif
                        </div>
                    </div>
                </div>
            </div>
        </div>
        @endif

        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Your Recent Posts</h5>
                    </div>
                    <div class="card-body">
                        @if(Auth::user()->posts()->count() > 0)
                            @foreach(Auth::user()->posts()->latest()->take(5)->get() as $post)
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <div>
                                        <strong>{{ $post->title }}</strong>
                                        <br>
                                        <small class="text-muted">{{ $post->status }} - {{ $post->created_at->diffForHumans() }}</small>
                                    </div>
                                    <a href="{{ route('posts.show', $post) }}" class="btn btn-sm btn-outline-primary">View</a>
                                </div>
                            @endforeach
                        @else
                            <p class="text-muted">No posts yet. <a href="{{ route('admin.posts.create') }}">Create your first post!</a></p>
                        @endif
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">Your Recent Comments</h5>
                    </div>
                    <div class="card-body">
                        @if(Auth::user()->comments()->count() > 0)
                            @foreach(Auth::user()->comments()->latest()->take(5)->get() as $comment)
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between">
                                        <strong>{{ Str::limit($comment->content, 50) }}</strong>
                                        <small class="text-muted">{{ $comment->created_at->diffForHumans() }}</small>
                                    </div>
                                    <small class="text-muted">On: {{ $comment->post->title }}</small>
                                </div>
                            @endforeach
                        @else
                            <p class="text-muted">No comments yet.</p>
                        @endif
                    </div>
                </div>
            </div>
        </div>
    </main>

    <footer class="bg-dark text-light mt-5 py-4">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <p>&copy; {{ date('Y') }} {{ config('app.name', 'Laravel') }}. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-end">
                    <p>Role: {{ ucfirst(Auth::user()->role) }}</p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
