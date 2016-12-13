package main

import "fmt"
import "math"

func main() {
	fmt.Println("hello world")

	fmt.Println("go" + "lang")

	fmt.Println(true && false)
	fmt.Println(true || false)

	var a string = "initial"
	fmt.Println(a)

	var b,c int = 1, 2
	fmt.Println(b,c)

	var d = true //Infer type
	fmt.Println(d)

	f := "short"
	fmt.Println(f)

	const n = 500

	const e = 3e20 / n

	fmt.Println(int64(e))

	fmt.Println(math.Sin(n))
}