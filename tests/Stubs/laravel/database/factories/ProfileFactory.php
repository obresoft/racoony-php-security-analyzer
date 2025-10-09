<?php

declare(strict_types=1);

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Profile>
 */
final class ProfileFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'user_id' => User::factory(),
            'bio' => fake()->optional()->paragraph(),
            'avatar' => fake()->optional()->imageUrl(200, 200, 'people'),
            'website' => fake()->optional()->url(),
            'location' => fake()->optional()->city() . ', ' . fake()->optional()->state(),
            'birth_date' => fake()->optional()->dateTimeBetween('-60 years', '-18 years'),
            'phone' => fake()->optional()->phoneNumber(),
            'social_links' => fake()->optional()->randomElements([
                'twitter' => fake()->url(),
                'linkedin' => fake()->url(),
                'github' => fake()->url(),
                'facebook' => fake()->url(),
            ], random_int(0, 4)),
            'preferences' => fake()->optional()->randomElements([
                'email_notifications' => fake()->boolean(),
                'newsletter' => fake()->boolean(),
                'theme' => fake()->randomElement(['light', 'dark']),
                'language' => fake()->randomElement(['en', 'es', 'fr', 'de']),
            ], random_int(0, 4)),
        ];
    }
}
