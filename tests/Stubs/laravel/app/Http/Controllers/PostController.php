<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Category;
use App\Models\Post;
use App\Models\Tag;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

final class PostController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $posts = Post::with(['user', 'category', 'tags'])
            ->published()
            ->orderBy('published_at', 'desc')
            ->paginate(10);

        return view('posts.index', compact('posts'));
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        $categories = Category::active()->get();
        $tags = Tag::active()->get();

        return view('posts.create', compact('categories', 'tags'));
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'excerpt' => 'nullable|string|max:500',
            'category_id' => 'required|exists:categories,id',
            'status' => 'required|in:draft,published',
            'featured_image' => 'nullable|string|max:255',
            'meta_title' => 'nullable|string|max:255',
            'meta_description' => 'nullable|string|max:500',
            'tags' => 'nullable|array',
            'tags.*' => 'exists:tags,id',
        ]);

        $post = Post::create([
            'title' => $validated['title'],
            'content' => $validated['content'],
            'excerpt' => $validated['excerpt'],
            'slug' => Str::slug($validated['title']),
            'category_id' => $validated['category_id'],
            'status' => $validated['status'],
            'featured_image' => $validated['featured_image'],
            'meta_title' => $validated['meta_title'],
            'meta_description' => $validated['meta_description'],
            'user_id' => auth()->id(),
            'published_at' => 'published' === $validated['status'] ? now() : null,
        ]);

        if (!empty($validated['tags'])) {
            $post->tags()->attach($validated['tags']);
        }

        return redirect()->route('posts.index')
            ->with('success', 'Post created successfully.');
    }

    /**
     * Display the specified resource.
     */
    public function show(Post $post)
    {
        $post->load(['user', 'category', 'tags', 'comments.user']);

        return view('posts.show', compact('post'));
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(Post $post)
    {
        $categories = Category::active()->get();
        $tags = Tag::active()->get();

        return view('posts.edit', compact('post', 'categories', 'tags'));
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, Post $post)
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'excerpt' => 'nullable|string|max:500',
            'category_id' => 'required|exists:categories,id',
            'status' => 'required|in:draft,published',
            'featured_image' => 'nullable|string|max:255',
            'meta_title' => 'nullable|string|max:255',
            'meta_description' => 'nullable|string|max:500',
            'tags' => 'nullable|array',
            'tags.*' => 'exists:tags,id',
        ]);

        $post->update([
            'title' => $validated['title'],
            'content' => $validated['content'],
            'excerpt' => $validated['excerpt'],
            'slug' => Str::slug($validated['title']),
            'category_id' => $validated['category_id'],
            'status' => $validated['status'],
            'featured_image' => $validated['featured_image'],
            'meta_title' => $validated['meta_title'],
            'meta_description' => $validated['meta_description'],
            'published_at' => 'published' === $validated['status'] && !$post->published_at ? now() : $post->published_at,
        ]);

        if (isset($validated['tags'])) {
            $post->tags()->sync($validated['tags']);
        }

        return redirect()->route('posts.index')
            ->with('success', 'Post updated successfully.');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Post $post)
    {
        $post->delete();

        return redirect()->route('posts.index')
            ->with('success', 'Post deleted successfully.');
    }

    /**
     * Display posts by category.
     */
    public function byCategory(Category $category)
    {
        $posts = $category->posts()
            ->with(['user', 'tags'])
            ->published()
            ->orderBy('published_at', 'desc')
            ->paginate(10);

        return view('posts.by-category', compact('category', 'posts'));
    }

    /**
     * Display posts by tag.
     */
    public function byTag(Tag $tag)
    {
        $posts = $tag->posts()
            ->with(['user', 'category'])
            ->published()
            ->orderBy('published_at', 'desc')
            ->paginate(10);

        return view('posts.by-tag', compact('tag', 'posts'));
    }

    /**
     * Toggle featured status.
     */
    public function toggleFeatured(Post $post)
    {
        $post->update(['is_featured' => !$post->is_featured]);

        return back()->with('success', 'Featured status updated.');
    }
}
