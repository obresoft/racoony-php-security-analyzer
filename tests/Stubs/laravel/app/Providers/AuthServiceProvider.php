<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;

use function in_array;

final class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        $this->registerPolicies();

        // Define gates for role-based authorization
        Gate::define('admin', static fn ($user) => 'admin' === $user->role);

        Gate::define('editor', static fn ($user) => in_array($user->role, ['admin', 'editor'], true));

        Gate::define('update-comment', static fn ($user, $comment) => $user->id === $comment->user_id || 'admin' === $user->role);

        Gate::define('delete-comment', static fn ($user, $comment) => $user->id === $comment->user_id || 'admin' === $user->role);

        Gate::define('approve-comment', static fn ($user) => in_array($user->role, ['admin', 'editor'], true));
    }
}
