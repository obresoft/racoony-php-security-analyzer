<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

final class Photo extends Model
{
    protected $table = 'photos';

    protected $guarded = [];

    protected $casts = [
        'meta' => 'array',
        'is_public' => 'int',
        'is_admin' => 'int',
    ];
}
