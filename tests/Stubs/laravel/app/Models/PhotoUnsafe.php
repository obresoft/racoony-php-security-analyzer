<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

final class PhotoUnsafe extends Model
{
    protected $table = 'photos';

    protected $fillable = ['*'];

    protected $casts = [
        'meta' => 'array',
        'is_public' => 'int',
        'is_admin' => 'int',
    ];
}
