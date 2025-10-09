<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Comment;
use App\Models\Post;
use Illuminate\Http\Request;

final class CommentController extends Controller
{
    /**
     * Store a newly created comment.
     */
    public function store(Request $request, Post $post)
    {
        $validated = $request->validate([
            'content' => 'required|string|max:1000',
            'parent_id' => 'nullable|exists:comments,id',
        ]);

        $comment = $post->comments()->create([
            'content' => $validated['content'],
            'user_id' => auth()->id(),
            'parent_id' => $validated['parent_id'] ?? null,
            'is_approved' => 'admin' === auth()->user()->role ? true : false,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]);

        return back()->with('success', 'Comment submitted successfully.');
    }

    /**
     * Update the specified comment.
     */
    public function update(Request $request, Comment $comment)
    {
        $this->authorize('update', $comment);

        $validated = $request->validate([
            'content' => 'required|string|max:1000',
        ]);

        $comment->update($validated);

        return back()->with('success', 'Comment updated successfully.');
    }

    /**
     * Remove the specified comment.
     */
    public function destroy(Comment $comment)
    {
        $this->authorize('delete', $comment);

        $comment->delete();

        return back()->with('success', 'Comment deleted successfully.');
    }

    /**
     * Approve the specified comment.
     */
    public function approve(Comment $comment)
    {
        $this->authorize('approve', $comment);

        $comment->update(['is_approved' => true]);

        return back()->with('success', 'Comment approved successfully.');
    }

    /**
     * Reject the specified comment.
     */
    public function reject(Comment $comment)
    {
        $this->authorize('approve', $comment);

        $comment->update(['is_approved' => false]);

        return back()->with('success', 'Comment rejected successfully.');
    }

    /**
     * Display comments for moderation.
     */
    public function moderation()
    {
        $pendingComments = Comment::with(['user', 'post'])
            ->where('is_approved', false)
            ->orderBy('created_at', 'desc')
            ->paginate(20);

        return view('comments.moderation', compact('pendingComments'));
    }
}
