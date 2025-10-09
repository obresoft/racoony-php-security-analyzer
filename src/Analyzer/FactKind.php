<?php

declare(strict_types=1);

namespace Obresoft\Racoony\Analyzer;

enum FactKind: string
{
    case FUNC_CALL = 'FuncCall';
    case NEW = 'New';
    case ARRAY_ACCESS = 'ArrayAccess';
    case CONCAT = 'Concat';
    case ConstFetch = 'ConstFetch';
    case Scalar = 'Scalar';
    case Ternary = 'Ternary';
    case Coalesce = 'Coalesce';
    case ChainedCall = 'ChainedCall';
    case Expression = 'Expression';
    case CallFromFunction = 'CallFromOtherFunction';
    case ConcatAssign = 'ConcatAssign';
    case Unknown = 'Unknown';
    case Closure = 'Closure';
    case ARROW_FUNCTION = 'ArrowFunction';
    case VARIABLE = 'Variable';
    case METHOD = 'Method';
}
