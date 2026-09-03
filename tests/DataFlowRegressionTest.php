<?php

declare(strict_types=1);

namespace PhpSentinel\Tests;

/**
 * Regression tests for the taint-analyzer scope and data-flow fixes.
 *
 * These guard the three high-priority fixes:
 *
 * 1. Scope isolation — analysing a function/method/closure body must not
 *    clobber the surrounding scope, and locals must not leak between functions.
 * 2. Branch-aware data flow — a value assigned (or made tainted) in a single
 *    branch of an if/switch must not be unconditionally propagated past the
 *    branch when it does not hold on every path.
 * 3. sprintf() XSS — `sprintf()` returns a string and must be reported only
 *    once, at the surrounding echo/print sink, and must still be caught when
 *    its result reaches an output sink.
 *
 * Most cases are exercised through the SEC002 (XSS) rule because the sink
 * (`echo` / `print`) makes the taint state directly observable.
 */
final class DataFlowRegressionTest extends TestCase
{
    // ---------------------------------------------------------------- scope --

    public function testFunctionBodyDoesNotClobberCallerScope(): void
    {
        // Regression: analysing `helper()` used to reset() the whole context,
        // wiping the taint of `$g` before it is echoed.
        $code = <<<'PHP'
            <?php
            $g = $_GET['a'];
            function helper(): void {
                $z = 1;
            }
            echo $g;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testNestedFunctionDoesNotLeakIntoFunctionAfter(): void
    {
        // A variable assigned in one function body must never be visible in a
        // later function.
        $code = <<<'PHP'
            <?php
            function first(): void {
                $x = $_GET['a'];
            }
            function second(): void {
                echo $x;
            }
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testClosureBodyDoesNotClobberCallerScope(): void
    {
        $code = <<<'PHP'
            <?php
            $g = $_GET['a'];
            $closure = function (): void {
                $inner = 'x';
            };
            echo $g;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    // --------------------------------------------------------- returns/params --

    public function testFunctionReturnTaintPropagatesToCaller(): void
    {
        $code = <<<'PHP'
            <?php
            function get(): string {
                return $_GET['a'];
            }
            echo get();
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testFunctionReturnOfTaintedParameterPropagates(): void
    {
        $code = <<<'PHP'
            <?php
            function pass($value) {
                return $value;
            }
            echo pass($_GET['x']);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testMethodParameterBoundFromTaintedCallSite(): void
    {
        // The echo lives inside the method body; the method is called with a
        // tainted argument, so the body sink must be reported.
        $code = <<<'PHP'
            <?php
            class Handler {
                public function show($value): void {
                    echo $value;
                }
            }
            (new Handler())->show($_GET['x']);
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testMethodParameterOfUncalledMethodNotTainted(): void
    {
        $code = <<<'PHP'
            <?php
            class Handler {
                public function show($value): void {
                    echo $value;
                }
            }
            // never called with tainted input
            (new Handler())->show('static');
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testFunctionReturnSanitizedIsNotReported(): void
    {
        $code = <<<'PHP'
            <?php
            function get(): string {
                return htmlspecialchars($_GET['a'], ENT_QUOTES, 'UTF-8');
            }
            echo get();
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    // ---------------------------------------------------------- branch merge --

    public function testSingleBranchAssignmentNotPropagatedPastBranch(): void
    {
        // $x is clean before the branch and tainted only when the branch runs;
        // must-taint merging means `echo $x` is not unconditionally reported.
        $code = <<<'PHP'
            <?php
            $x = 'safe';
            if ($cond) {
                $x = $_GET['a'];
            }
            echo $x;
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSingleBranchAssignmentInsideFunctionNotPropagated(): void
    {
        $code = <<<'PHP'
            <?php
            function render(): void {
                if ($cond) {
                    $x = $_GET['a'];
                }
                echo $x;
            }
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testBothBranchesTaintedIsReported(): void
    {
        $code = <<<'PHP'
            <?php
            if ($cond) {
                $x = $_GET['a'];
            } else {
                $x = $_GET['b'];
            }
            echo $x;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSwitchSingleCaseTaintedNotPropagatedPastSwitch(): void
    {
        $code = <<<'PHP'
            <?php
            $x = 'safe';
            switch ($mode) {
                case 1:
                    $x = $_GET['a'];
                    break;
            }
            echo $x;
            PHP;

        self::assertSame([], $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSwitchTaintedBeforeStructureStillReportedAfter(): void
    {
        // Taint that exists before the branch structure must be preserved.
        $code = <<<'PHP'
            <?php
            $x = $_GET['a'];
            switch ($mode) {
                case 1:
                    $other = 'x';
                    break;
            }
            echo $x;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    // -------------------------------------------------------------- sprintf --

    public function testEchoOfSprintfResultReportedOnce(): void
    {
        // Regression: `echo sprintf(...)` used to be reported twice — once by
        // the sprintf FuncCall handler and once by the echo handler.
        $code = <<<'PHP'
            <?php
            $s = sprintf('<b>%s</b>', $_GET['name']);
            echo $s;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSprintfWithTaintedFormatStringReported(): void
    {
        $code = <<<'PHP'
            <?php
            echo sprintf($_GET['fmt'], 'value');
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }

    public function testSprintfResultAssignedAndEchoedSeparatelyReported(): void
    {
        $code = <<<'PHP'
            <?php
            $s = sprintf($_GET['name'], 'x');
            print $s;
            PHP;

        self::assertCount(1, $this->analyzeWithRule($code, 'SEC002'));
    }
}
