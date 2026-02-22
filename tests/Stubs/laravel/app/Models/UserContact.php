<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Obresoft\Racoony\Attribute\SensitiveFieldsAttribute;

#[SensitiveFieldsAttribute(['email', 'first_name'])]
final class UserContact extends Model
{
    protected $fillable = [
        'user_id',
        'first_name',
        'last_name',
        'avatar_path',
        'email',
    ];

    protected $casts = [
        'user_id' => 'int',
    ];
}
